# Online Voting System

## Project Description
An Online Voting System that allows users to register as voters or admins, manage elections, candidates, and votes through an admin panel, and securely cast votes. The system supports admin approval of voter registrations and provides a comprehensive admin dashboard.

## Features
- User registration with roles (voter/admin)
- Admin approval for voter registrations
- Admin panel with sections for:
  - Vote Summary
  - Voters List (add, edit, delete voters)
  - Candidate List (add, edit, delete candidates)
  - Elections (add, edit, delete elections)
  - Pending Voter Requests (approve/reject)
- Secure login with session management
- Separate admin databases for multi-tenant support
- SQLite database backend

## Technologies Used
- Node.js with Express.js for backend API
- SQLite for database
- HTML, CSS, JavaScript for frontend
- bcrypt for password hashing
- express-session with SQLite store for session management

## Setup and Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd online-voting-system
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the root directory and set the following environment variable:
   ```
   SESSION_SECRET=your_secret_key
   ```

4. Initialize the main database:
   ```
   node db-init.js
   ```

5. Start the server:
   ```
   node server.js
   ```

6. Open your browser and navigate to:
   ```
   http://localhost:3002/
   ```

## Usage

### Voter
- Register as a voter via the registration page.
- Wait for admin approval.
- Once approved, log in and participate in elections.

### Admin
- Register as an admin.
- Receive an admin access code upon registration.
- Log in with username and password, then enter the admin access code.
- Access the admin panel to manage voters, candidates, elections, and view vote summaries.
- Approve or reject pending voter registration requests.

## Folder Structure

- `public/` - Frontend HTML, CSS, and image assets
- `server.js` - Main backend server and API routes
- `db-init.js` - Database initialization script
- `db-migrate.js` - Database migration script (if applicable)
- `package.json` - Node.js project manifest
- `admin_dbs/` - Directory for separate admin databases (created at runtime)
- `voting.db` - Main SQLite database file (created at runtime)

## Notes
- The system uses separate SQLite databases for each admin to support multi-tenancy.
- Sessions are managed using express-session with SQLite store.
- Passwords are securely hashed using bcrypt.
- Admin access code is required for admin login verification.

## Download
You can download the project as a ZIP file from the repository hosting service or clone it using Git:


git clone <repository-url>
Replace <repository-url> with the actual URL of the repository.

This will help users to download or clone the project easily.