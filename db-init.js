const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbFilePath = process.argv[2] || './voting.db';
const db = new sqlite3.Database(dbFilePath);

db.serialize(() => {
  // Drop existing tables to ensure fresh schema
  db.run('DROP TABLE IF EXISTS users');
  db.run('DROP TABLE IF EXISTS voters');
  db.run('DROP TABLE IF EXISTS votes');
  db.run('DROP TABLE IF EXISTS elections');
  db.run('DROP TABLE IF EXISTS candidates');
  db.run('DROP TABLE IF EXISTS candidate_requests');

  // Create users table with email column and is_approved column
  db.run("CREATE TABLE users (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "first_name TEXT NOT NULL," +
    "last_name TEXT NOT NULL," +
    "username TEXT UNIQUE NOT NULL," +
    "password TEXT NOT NULL," +
    "email TEXT UNIQUE NOT NULL," +
    "is_admin INTEGER DEFAULT 0," +
    "is_approved INTEGER DEFAULT 0" +
  ")");

  // Create voters table
  db.run("CREATE TABLE voters (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "name TEXT NOT NULL," +
    "email TEXT UNIQUE NOT NULL," +
    "has_voted INTEGER DEFAULT 0" +
  ")");

  // Create votes table
  db.run("CREATE TABLE votes (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "voter_id INTEGER NOT NULL," +
    "candidate_id INTEGER NOT NULL," +
    "election_id INTEGER," +
    "FOREIGN KEY (voter_id) REFERENCES voters(id)," +
    "FOREIGN KEY (candidate_id) REFERENCES candidates(id)" +
  ")");

  // Create elections table with unique code
  db.run("CREATE TABLE elections (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "name TEXT NOT NULL," +
    "start_time TEXT NOT NULL," +
    "end_time TEXT NOT NULL," +
    "code TEXT UNIQUE NOT NULL" +
  ")");

  // Create candidates table
  db.run("CREATE TABLE candidates (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "name TEXT NOT NULL," +
    "election_id INTEGER," +
    "FOREIGN KEY (election_id) REFERENCES elections(id)" +
  ")");

  // Create candidate_requests table
  db.run("CREATE TABLE candidate_requests (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "first_name TEXT NOT NULL," +
    "last_name TEXT NOT NULL," +
    "username TEXT UNIQUE NOT NULL," +
    "password TEXT NOT NULL," +
    "email TEXT UNIQUE NOT NULL," +
    "election_id INTEGER NOT NULL," +
    "status TEXT NOT NULL DEFAULT 'pending'," +
    "FOREIGN KEY (election_id) REFERENCES elections(id)" +
  ")");

  console.log('Database initialized at ' + dbFilePath);
});

db.close();
