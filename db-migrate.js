const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const dbPath = path.resolve(__dirname, 'voting.db');

// Delete existing database file
if (fs.existsSync(dbPath)) {
  fs.unlinkSync(dbPath);
  console.log('Deleted existing voting.db file');
} else {
  console.log('No existing voting.db file found');
}

// Run db-init.js to recreate tables
exec('node db-init.js', (error, stdout, stderr) => {
  if (error) {
    console.error(`Error running db-init.js: ${error.message}`);
    return;
  }
  if (stderr) {
    console.error(`Error output from db-init.js: ${stderr}`);
    return;
  }
  console.log('Database initialized successfully:');
  console.log(stdout);
});
