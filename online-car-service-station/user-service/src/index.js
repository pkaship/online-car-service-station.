// user-service/src/index.js
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based version for async/await
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // For handling Cross-Origin Resource Sharing

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies
app.use(cors()); // Enable CORS for all origins (for development, restrict in production)

// Database Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,        // 'user-db' when running within docker-compose network, or 'localhost' if running on host directly and connecting to exposed port 3306
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// JWT Secret (generate a strong one for production)
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expects 'Bearer TOKEN'

  if (!token) {
    return res.status(401).json({ message: 'Access Denied: No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ message: 'Access Denied: Invalid token' });
    }
    req.user = user; // Attach user payload to the request
    next();
  });
};

// Routes

// 1. Register User (Public Endpoint)
app.post('/api/users/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Username, email, and password are required' });
  }

  try {
    const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(409).json({ message: 'User with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10); // Hash password
    const userRole = role || 'customer'; // Default role to 'customer'

    const [result] = await pool.query('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', [
      username,
      email,
      hashedPassword,
      userRole
    ]);
    res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error during registration' });
  }
});

// 2. Login User (Public Endpoint)
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const [users] = await pool.query('SELECT id, username, email, password, role FROM users WHERE email = ?', [email]);
    const user = users[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' } // Token expires in 1 hour
    );
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error during login' });
  }
});

// 3. Get User Profile (Protected Endpoint - requires JWT)
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, username, email, role, created_at FROM users WHERE id = ?', [req.user.id]);
    const user = users[0];
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 4. Update User Profile (Protected Endpoint - requires JWT)
app.put('/api/users/profile', authenticateToken, async (req, res) => {
  const { username, email } = req.body; // Password change would be a separate endpoint for security reasons
  const userId = req.user.id; // User ID from the JWT token

  if (!username || !email) {
    return res.status(400).json({ message: 'Username and email are required for update' });
  }

  try {
    const [result] = await pool.query('UPDATE users SET username = ?, email = ? WHERE id = ?', [username, email, userId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found or no changes made' });
    }
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Internal server error during profile update' });
  }
});

// 5. Delete User (Protected Endpoint - requires JWT and authorization)
// Allows self-deletion or admin deletion
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  const userIdToDelete = parseInt(req.params.id, 10); // Ensure ID is an integer

  // Authorization check: User can delete their own account OR an admin can delete any account
  if (req.user.id !== userIdToDelete && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden: You are not authorized to delete this user' });
  }

  try {
    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [userIdToDelete]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ message: 'Internal server error during user deletion' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`User Service running on port ${PORT}`);
});

// Initialize database schema (create table if not exists)
async function initializeDb() {
  try {
    const connection = await pool.getConnection();
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('customer', 'admin', 'mechanic') DEFAULT 'customer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('User table checked/created successfully.');
    connection.release();
  } catch (error) {
    console.error('Error initializing user database:', error);
    // In a real application, you might want to log this and retry or alert.
    // For Codespaces dev, exiting is okay if DB is critical.
    process.exit(1);
  }
}

initializeDb();