require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3002;

const mainDbPath = path.resolve(__dirname, 'voting.db');
const mainDb = new sqlite3.Database(mainDbPath, (err) => {
  if (err) console.error('Error opening main database:', err.message);
  else console.log('Connected to main SQLite database.');
});

// Temporary in-memory store for admin login tokens
const adminLoginTokens = new Map();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  store: new SQLiteStore,
  secret: process.env.SESSION_SECRET || 'default-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 600000, sameSite: 'lax', secure: false }
}));
app.use(express.static(path.join(__dirname, 'public')));

// Create admin_databases table in main DB if not exists
mainDb.run(`
  CREATE TABLE IF NOT EXISTS admin_databases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    db_path TEXT NOT NULL,
    admin_access_code TEXT NOT NULL
  )
`);

// Helpers
function isAuthenticated(req, res, next) {
  if (req.session.userId) next();
  else res.redirect('/');
}

function isAdmin(req, res, next) {
  if (req.session.isAdmin) next();
  else res.status(403).send('Forbidden: Admins only');
}

// Function to initialize a new admin database
function initializeAdminDatabase(dbFilePath, callback) {
  const initScript = path.resolve(__dirname, 'db-init.js');
  const command = `node db-init.js "${dbFilePath}"`;
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error initializing admin DB: ${error.message}`);
      callback(error);
      return;
    }
    if (stderr) {
      console.error(`Stderr initializing admin DB: ${stderr}`);
    }
    console.log(`Admin DB initialized: ${stdout}`);
    callback(null);
  });
}

// Generate random admin access code
function generateAdminAccessCode() {
  return crypto.randomBytes(4).toString('hex'); // 8 char hex string
}

// Endpoint to approve candidate requests
app.put('/admin/pending-candidates/:id/approve', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const candidateId = req.params.id;

  // Get candidate request data
  mainDb.get('SELECT * FROM candidate_requests WHERE id = ?', [candidateId], (err, candidate) => {
    if (err) return res.status(500).send('Database error');
    if (!candidate) return res.status(404).send('Candidate request not found');

    // Insert candidate into users table with is_admin=0, is_approved=1
    const insertUserStmt = mainDb.prepare('INSERT INTO users (first_name, last_name, username, password, email, is_admin, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)');
    insertUserStmt.run(candidate.first_name, candidate.last_name, candidate.username, candidate.password, candidate.email, 0, 1, function (insertErr) {
      if (insertErr) return res.status(500).send('Database error inserting candidate user');

      // Insert candidate into voters table
      const insertVoterStmt = mainDb.prepare('INSERT INTO voters (name, email) VALUES (?, ?)');
      insertVoterStmt.run(candidate.first_name + ' ' + candidate.last_name, candidate.email, function (voterErr) {
        if (voterErr) {
          console.error('Error inserting candidate into voters table:', voterErr.message);
          // Continue anyway
        }
        insertVoterStmt.finalize();

        // Delete candidate request
        const deleteStmt = mainDb.prepare('DELETE FROM candidate_requests WHERE id = ?');
        deleteStmt.run(candidateId, function (deleteErr) {
          if (deleteErr) return res.status(500).send('Database error deleting candidate request');
          res.send('Candidate approved and added successfully');
        });
        deleteStmt.finalize();
      });
    });
    insertUserStmt.finalize();
  });
});

// Login route supporting multi-tenant databases with token-based admin access code verification
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sanitizedUsername = username.trim();

  mainDb.get('SELECT db_path, admin_access_code FROM admin_databases WHERE username = ?', [sanitizedUsername], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });

    const dbPath = row ? row.db_path : mainDbPath;
    const userDb = new sqlite3.Database(dbPath);

    userDb.get('SELECT * FROM users WHERE username = ?', [sanitizedUsername], async (err, user) => {
      if (err) {
        userDb.close();
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (!user) {
        userDb.close();
        return res.status(400).json({ success: false, message: 'User not found' });
      }
      if (user.is_approved === 0) {
        userDb.close();
        return res.status(403).json({ success: false, message: 'User not approved yet' });
      }

      // For admin users, check if any election is currently active
      if (user.is_admin === 1) {
        const now = new Date().toISOString();
        mainDb.get('SELECT * FROM elections WHERE start_time <= ? AND end_time >= ?', [now, now], async (err, activeElection) => {
          if (err) {
            userDb.close();
            return res.status(500).json({ success: false, message: 'Database error checking elections' });
          }
          if (activeElection) {
            // If election ongoing, log in admin as voter
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
              userDb.close();
              return res.status(400).json({ success: false, message: 'Invalid username or password' });
            }
            userDb.close();
            req.session.userId = user.id;
            req.session.isAdmin = false;
            return res.json({ success: true, isAdmin: false });
          }

          // No ongoing election, proceed with admin login
          const match = await bcrypt.compare(password, user.password);
          if (!match) {
            userDb.close();
            return res.status(400).json({ success: false, message: 'Invalid username or password' });
          }

          // Generate a temporary token for admin access code verification
          const token = uuidv4();

          // Store token and admin access code in memory
          if (row) {
            adminLoginTokens.set(token, { adminAccessCode: row.admin_access_code, userId: user.id, isAdmin: true });
          }

          userDb.close();

          // Send token to client to proceed with admin access code verification
          res.json({ success: true, isAdmin: true, token });
        });
      } else {
        // For non-admin users, continue with password check
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          userDb.close();
          return res.status(400).json({ success: false, message: 'Invalid username or password' });
        }
        userDb.close();
        req.session.userId = user.id;
        req.session.isAdmin = false;
        res.json({ success: true, isAdmin: false });
      }
    });
  });
});

// Route to verify admin access code with token
app.post('/verify-admin-code', (req, res) => {
  const { token, code } = req.body;
  const record = adminLoginTokens.get(token);

  if (!record) {
    return res.status(400).json({ success: false, message: 'Invalid or expired token' });
  }

  if (code && code.trim().toLowerCase() === record.adminAccessCode.trim().toLowerCase()) {
    // Create session for admin user
    req.session.userId = record.userId;
    req.session.isAdmin = record.isAdmin;
    req.session.adminAccessGranted = true;

    // Remove token from store
    adminLoginTokens.delete(token);

    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ success: false, message: 'Session error' });
      }
      res.json({ success: true });
    });
  } else {
    res.json({ success: false, message: 'Invalid admin access code' });
  }
});

function getUserDb(req, callback) {
  if (!req.session.userId) {
    // No user session, use mainDb
    return callback(null, mainDb);
  }
  if (!req.session.isAdmin) {
    // Non-admin user, use mainDb
    return callback(null, mainDb);
  }
  // Admin user: get username from users table first
  mainDb.get('SELECT username FROM users WHERE id = ?', [req.session.userId], (err, userRow) => {
    if (err || !userRow) {
      console.error('Error fetching username for admin user:', err);
      return callback(null, mainDb);
    }
    const username = userRow.username;
    // Then get admin DB path from admin_databases table
    mainDb.get('SELECT db_path FROM admin_databases WHERE username = ?', [username], (err, adminRow) => {
      if (err || !adminRow) {
        console.error('Error fetching admin database for username:', username, err);
        return callback(null, mainDb);
      }
      const adminDb = new sqlite3.Database(adminRow.db_path);
      callback(null, adminDb);
    });
  });
}

// Middleware to check admin role for admin routes
function checkAdminRole(req, res, next) {
  if (req.session.isAdmin && req.session.adminAccessGranted) {
    next();
  } else {
    res.status(403).send('Forbidden: Admin access code required');
  }
}

// Example protected admin route
app.get('/admin/dashboard', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Route to serve admin access code entry page
app.get('/admin-access-code', isAuthenticated, isAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-access-code.html'));
});

// Existing endpoints for voters
app.get('/admin/voters', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  getUserDb(req, (err, db) => {
    if (err) return res.status(500).send('Database error');
    db.all('SELECT * FROM voters', (err, rows) => {
      if (err) return res.status(500).send('Database error');
      res.json(rows);
    });
  });
});

app.post('/admin/add-voter', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const { name, email } = req.body;
  getUserDb(req, (err, db) => {
    if (err) return res.status(500).send('Database error');
    const stmt = db.prepare('INSERT INTO voters (name, email) VALUES (?, ?)');
    stmt.run(name, email, function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed'))
          return res.status(400).send('Email already exists');
        return res.status(500).send('Database error');
      }
      res.status(201).send('Voter added successfully');
    });
    stmt.finalize();
  });
});

app.put('/admin/voters/:id', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const voterId = req.params.id;
  const { name, email, has_voted } = req.body;
  getUserDb(req, (err, db) => {
    if (err) return res.status(500).send('Database error');
    const stmt = db.prepare('UPDATE voters SET name = ?, email = ?, has_voted = ? WHERE id = ?');
    stmt.run(name, email, has_voted ? 1 : 0, voterId, function (err) {
      if (err) return res.status(500).send('Database error');
      if (this.changes === 0) return res.status(404).send('Voter not found');
      res.send('Voter updated successfully');
    });
    stmt.finalize();
  });
});

app.delete('/admin/voters/:id', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const voterId = req.params.id;
  getUserDb(req, (err, db) => {
    if (err) return res.status(500).send('Database error');
    const stmt = db.prepare('DELETE FROM voters WHERE id = ?');
    stmt.run(voterId, function (err) {
      if (err) return res.status(500).send('Database error');
      if (this.changes === 0) return res.status(404).send('Voter not found');
      res.send('Voter deleted successfully');
    });
    stmt.finalize();
  });
});

// New endpoints for candidates
app.get('/admin/candidates', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  mainDb.all('SELECT * FROM candidates', (err, rows) => {
    if (err) return res.status(500).send('Database error');
    res.json(rows);
  });
});

app.post('/admin/candidates', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const { name, election_id } = req.body;
  const stmt = mainDb.prepare('INSERT INTO candidates (name, election_id) VALUES (?, ?)');
  stmt.run(name, election_id || null, function (err) {
    if (err) return res.status(500).send('Database error');
    res.status(201).send('Candidate added successfully');
  });
  stmt.finalize();
});

app.put('/admin/candidates/:id', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const candidateId = req.params.id;
  const { name, election_id } = req.body;
  const stmt = mainDb.prepare('UPDATE candidates SET name = ?, election_id = ? WHERE id = ?');
  stmt.run(name, election_id || null, candidateId, function (err) {
    if (err) return res.status(500).send('Database error');
    if (this.changes === 0) return res.status(404).send('Candidate not found');
    res.send('Candidate updated successfully');
  });
  stmt.finalize();
});

app.delete('/admin/candidates/:id', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const candidateId = req.params.id;
  const stmt = mainDb.prepare('DELETE FROM candidates WHERE id = ?');
  stmt.run(candidateId, function (err) {
    if (err) return res.status(500).send('Database error');
    if (this.changes === 0) return res.status(404).send('Candidate not found');
    res.send('Candidate deleted successfully');
  });
  stmt.finalize();
});

// Elections endpoints
app.get('/admin/elections', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  mainDb.all('SELECT * FROM elections', (err, rows) => {
    if (err) return res.status(500).send('Database error');
    res.json(rows);
  });
});

app.post('/admin/elections', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const { name, start_time, end_time } = req.body;
  const stmt = mainDb.prepare('INSERT INTO elections (name, start_time, end_time) VALUES (?, ?, ?)');
  stmt.run(name, start_time, end_time, function (err) {
    if (err) return res.status(500).send('Database error');
    res.status(201).send('Election added successfully');
  });
  stmt.finalize();
});

app.put('/admin/elections/:id', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const electionId = req.params.id;
  const { name, start_time, end_time } = req.body;
  const stmt = mainDb.prepare('UPDATE elections SET name = ?, start_time = ?, end_time = ? WHERE id = ?');
  stmt.run(name, start_time, end_time, electionId, function (err) {
    if (err) return res.status(500).send('Database error');
    if (this.changes === 0) return res.status(404).send('Election not found');
    res.send('Election updated successfully');
  });
  stmt.finalize();
});

app.delete('/admin/elections/:id', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const electionId = req.params.id;

  mainDb.serialize(() => {
    mainDb.run('BEGIN TRANSACTION', (beginErr) => {
      if (beginErr) {
        return res.status(500).send('Database error starting transaction');
      }

      // Delete votes related to the election
      mainDb.run('DELETE FROM votes WHERE election_id = ?', [electionId], function (err) {
        if (err) {
          mainDb.run('ROLLBACK');
          return res.status(500).send('Database error deleting votes');
        }

        // Delete candidates related to the election
        mainDb.run('DELETE FROM candidates WHERE election_id = ?', [electionId], function (err) {
          if (err) {
            mainDb.run('ROLLBACK');
            return res.status(500).send('Database error deleting candidates');
          }

          // Delete the election itself
          mainDb.run('DELETE FROM elections WHERE id = ?', [electionId], function (err) {
            if (err) {
              mainDb.run('ROLLBACK');
              return res.status(500).send('Database error deleting election');
            }
            if (this.changes === 0) {
              mainDb.run('ROLLBACK');
              return res.status(404).send('Election not found');
            }

            mainDb.run('COMMIT', (commitErr) => {
              if (commitErr) {
                return res.status(500).send('Database error committing transaction');
              }
              res.send('Election and related data deleted successfully');
            });
          });
        });
      });
    });
  });
});

app.get('/admin/pending-voters', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  mainDb.all('SELECT * FROM users WHERE is_approved = 0 AND is_admin = 0', (err, rows) => {
    if (err) return res.status(500).send('Database error');
    res.json(rows);
  });
});

app.put('/admin/pending-voters/:id/approve', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const userId = req.params.id;

  // First, get the user data from users table
  mainDb.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) return res.status(500).send('Database error');
    if (!user) return res.status(404).send('User not found');

    // Insert user data into voters table
    const insertStmt = mainDb.prepare('INSERT INTO voters (name, email) VALUES (?, ?)');
    insertStmt.run(user.first_name + ' ' + user.last_name, user.email, function (insertErr) {
      if (insertErr) {
        insertStmt.finalize();
        return res.status(500).send('Database error inserting voter');
      }

      insertStmt.finalize();

      // Update users table to set is_approved = 1
      const updateStmt = mainDb.prepare('UPDATE users SET is_approved = 1 WHERE id = ?');
      updateStmt.run(userId, function (updateErr) {
        if (updateErr) return res.status(500).send('Database error updating user approval');
        if (this.changes === 0) return res.status(404).send('User not found');
        res.send('User approved and added to voters successfully');
      });
      updateStmt.finalize();
    });
  });
});

app.put('/admin/pending-voters/:id/reject', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const userId = req.params.id;
  const stmt = mainDb.prepare('DELETE FROM users WHERE id = ?');
  stmt.run(userId, function (err) {
    if (err) return res.status(500).send('Database error');
    if (this.changes === 0) return res.status(404).send('User not found');
    res.send('User rejected and deleted successfully');
  });
  stmt.finalize();
});

app.get('/candidates', isAuthenticated, (req, res) => {
  const electionId = req.query.election_id;
  if (!electionId) {
    return res.status(400).send('Election ID is required');
  }
  mainDb.all('SELECT * FROM candidates WHERE election_id = ?', [electionId], (err, rows) => {
    if (err) return res.status(500).send('Database error');
    res.json(rows);
  });
});

app.post('/vote', isAuthenticated, (req, res) => {
  const voterId = req.session.userId;
  const { candidate_id } = req.body;

  if (!candidate_id) {
    return res.status(400).send('Candidate ID is required');
  }

  // Get election_id for the candidate
  mainDb.get('SELECT election_id FROM candidates WHERE id = ?', [candidate_id], (err, candidate) => {
    if (err) return res.status(500).send('Database error');
    if (!candidate) return res.status(404).send('Candidate not found');

    const electionId = candidate.election_id;

    // Check if voter has already voted in this election
    mainDb.get('SELECT * FROM votes WHERE voter_id = ? AND election_id = ?', [voterId, electionId], (err, vote) => {
      if (err) return res.status(500).send('Database error');
      if (vote) return res.status(400).send('You have already voted in this election');

      // Insert vote
      const stmt = mainDb.prepare('INSERT INTO votes (voter_id, candidate_id, election_id) VALUES (?, ?, ?)');
      stmt.run(voterId, candidate_id, electionId, function (err) {
        if (err) return res.status(500).send('Database error');

        // Update voter's has_voted status
        mainDb.run('UPDATE voters SET has_voted = 1 WHERE id = ?', [voterId], (err) => {
          if (err) return res.status(500).send('Database error updating voter status');
          res.send('Vote cast successfully');
        });
      });
      stmt.finalize();
    });
  });
});

app.get('/elections', isAuthenticated, (req, res) => {
  mainDb.all('SELECT * FROM elections', (err, rows) => {
    if (err) return res.status(500).send('Database error');
    res.json(rows);
  });
});

app.get('/admin/vote-summary', isAuthenticated, isAdmin, checkAdminRole, (req, res) => {
  const now = new Date().toISOString();
  // Check if any election is ongoing
  mainDb.get('SELECT * FROM elections WHERE start_time <= ? AND end_time >= ?', [now, now], (err, ongoingElection) => {
    if (err) {
      console.error('Error checking ongoing elections:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    if (ongoingElection) {
      // During ongoing election, do not show vote summary
      return res.status(403).json({ error: 'Vote summary not available during ongoing election' });
    }
    // Fetch vote summary only for ended elections
    const query = `
      SELECT e.id AS election_id, e.name AS election_name, c.id AS candidate_id, c.name AS candidate_name, COUNT(v.id) AS vote_count
      FROM elections e
      LEFT JOIN candidates c ON c.election_id = e.id
      LEFT JOIN votes v ON v.candidate_id = c.id
      WHERE e.end_time < ?
      GROUP BY e.id, c.id
      ORDER BY e.id, vote_count DESC
    `;
    mainDb.all(query, [now], (err, rows) => {
      if (err) {
        console.error('Error fetching vote summary:', err);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      // Group results by election_id
      const resultsByElection = {};
      rows.forEach(row => {
        if (!resultsByElection[row.election_id]) {
          resultsByElection[row.election_id] = {
            election_name: row.election_name,
            candidates: []
          };
        }
        resultsByElection[row.election_id].candidates.push({
          candidate_id: row.candidate_id,
          candidate_name: row.candidate_name || 'No Candidate',
          vote_count: row.vote_count
        });
      });
      res.json(resultsByElection);
    });
  });
});

app.get('/results', isAuthenticated, (req, res) => {
  const electionId = req.query.election_id;
  if (!electionId) {
    return res.status(400).json({ error: 'Election ID is required' });
  }
  const now = new Date().toISOString();
  // Check if election has ended
  mainDb.get('SELECT * FROM elections WHERE id = ? AND end_time < ?', [electionId, now], (err, endedElection) => {
    if (err) {
      console.error('Error checking election end time:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    if (!endedElection) {
      // Election not ended yet, do not show results
      return res.status(403).json({ error: 'Election results not available until election ends' });
    }
    const query = `
      SELECT c.id AS candidate_id, c.name AS candidate_name, COUNT(v.id) AS vote_count
      FROM candidates c
      LEFT JOIN votes v ON v.candidate_id = c.id
      WHERE c.election_id = ?
      GROUP BY c.id
      ORDER BY vote_count DESC
    `;
    mainDb.all(query, [electionId], (err, rows) => {
      if (err) {
        console.error('Error fetching election results:', err);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      res.json({
        election_id: electionId,
        results: rows.map(row => ({
          candidate_id: row.candidate_id,
          candidate_name: row.candidate_name,
          vote_count: row.vote_count
        }))
      });
    });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sanitizedUsername = username.trim();

  mainDb.get('SELECT db_path, admin_access_code FROM admin_databases WHERE username = ?', [sanitizedUsername], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });

    const dbPath = row ? row.db_path : mainDbPath;
    const userDb = new sqlite3.Database(dbPath);

    userDb.get('SELECT * FROM users WHERE username = ?', [sanitizedUsername], async (err, user) => {
      if (err) {
        userDb.close();
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (!user) {
        userDb.close();
        return res.status(400).json({ success: false, message: 'User not found' });
      }
      if (user.is_approved === 0) {
        userDb.close();
        return res.status(403).json({ success: false, message: 'User not approved yet' });
      }

      // For admin users, check if any election is currently active
      if (user.is_admin === 1) {
        const now = new Date().toISOString();
        mainDb.get('SELECT * FROM elections WHERE start_time <= ? AND end_time >= ?', [now, now], async (err, activeElection) => {
          if (err) {
            userDb.close();
            return res.status(500).json({ success: false, message: 'Database error checking elections' });
          }
          if (activeElection) {
            userDb.close();
            return res.status(403).json({ success: false, message: 'Admin login forbidden during ongoing election' });
          }

          // No ongoing election, proceed with admin login
          const match = await bcrypt.compare(password, user.password);
          if (!match) {
            userDb.close();
            return res.status(400).json({ success: false, message: 'Invalid username or password' });
          }

          // Generate a temporary token for admin access code verification
          const token = uuidv4();

          // Store token and admin access code in memory
          if (row) {
            adminLoginTokens.set(token, { adminAccessCode: row.admin_access_code, userId: user.id, isAdmin: true });
          }

          userDb.close();

          // Send token to client to proceed with admin access code verification
          res.json({ success: true, isAdmin: true, token });
        });
      } else {
        // For non-admin users, continue with password check
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          userDb.close();
          return res.status(400).json({ success: false, message: 'Invalid username or password' });
        }
        userDb.close();
        req.session.userId = user.id;
        req.session.isAdmin = false;
        res.json({ success: true, isAdmin: false });
      }
    });
  });
});

// New endpoint for user registration
app.post('/register', async (req, res) => {
  const { first_name, last_name, username, email, password, confirm_password, role, election_id } = req.body;

  if (!first_name || !last_name || !username || !email || !password || !confirm_password || !role) {
    return res.status(400).send('All required fields must be filled');
  }

  if (password !== confirm_password) {
    return res.status(400).send('Passwords do not match');
  }

  const isAdmin = role === 'admin' ? 1 : 0;
  const isCandidate = role === 'candidate' ? 1 : 0;

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert user into users table with is_approved=1 for admin, 0 for others (pending approval)
  const isApproved = isAdmin ? 1 : 0;
  const insertUserStmt = mainDb.prepare('INSERT INTO users (first_name, last_name, username, password, email, is_admin, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)');
  insertUserStmt.run(first_name, last_name, username, hashedPassword, email, isAdmin, isApproved, function (err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).send('Username or email already exists');
      }
      return res.status(500).send('Database error');
    }

    const userId = this.lastID;

    if (isAdmin) {
      // Generate admin access code
      const adminAccessCode = generateAdminAccessCode();

      // Create admin database file path
      const adminDbFilePath = path.resolve(__dirname, 'admin_dbs', `${username}_admin.db`);

      // Ensure admin_dbs directory exists
      const adminDbsDir = path.resolve(__dirname, 'admin_dbs');
      if (!fs.existsSync(adminDbsDir)) {
        fs.mkdirSync(adminDbsDir);
        console.log('Created admin_dbs directory at', adminDbsDir);
      }

      // Insert into admin_databases table
      const insertAdminDbStmt = mainDb.prepare('INSERT INTO admin_databases (username, db_path, admin_access_code) VALUES (?, ?, ?)');
      insertAdminDbStmt.run(username, adminDbFilePath, adminAccessCode, (adminDbErr) => {
        if (adminDbErr) {
          return res.status(500).send('Database error inserting admin database info');
        }
        insertAdminDbStmt.finalize();

        // Initialize admin database
          initializeAdminDatabase(adminDbFilePath, (initErr) => {
            if (initErr) {
              return res.status(500).send('Error initializing admin database');
            }
            // Insert admin user into admin database users table
            const adminDb = new sqlite3.Database(adminDbFilePath);
            const insertAdminUserStmt = adminDb.prepare('INSERT INTO users (first_name, last_name, username, password, email, is_admin, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)');
            insertAdminUserStmt.run(first_name, last_name, username, hashedPassword, email, 1, 1, function (insertErr) {
              if (insertErr) {
                console.error('Error inserting admin user into admin database:', insertErr);
                return res.status(500).send('Error inserting admin user into admin database');
              }
              insertAdminUserStmt.finalize();
              adminDb.close();
              // Set session for admin user
              req.session.userId = userId;
              req.session.isAdmin = true;
              req.session.save((err) => {
                if (err) {
                  console.error('Session save error:', err);
                  return res.status(500).send('Session error');
                }
                res.redirect(`/admin-welcome.html?code=${adminAccessCode}`);
              });
            });
          });
      });
    } else if (isCandidate) {
      // Insert candidate into candidates table with election_id
      const insertCandidateStmt = mainDb.prepare('INSERT INTO candidates (name, election_id) VALUES (?, ?)');
      insertCandidateStmt.run(first_name + ' ' + last_name, election_id || null, (candidateErr) => {
        if (candidateErr) {
          return res.status(500).send('Database error inserting candidate');
        }
        insertCandidateStmt.finalize();
        res.status(201).send('Registration successful. Awaiting approval.');
      });
    } else {
      res.status(201).send('Registration successful. Awaiting approval.');
    }
  });
  insertUserStmt.finalize();
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = { app, mainDb };
