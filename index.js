const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

dotenv.config();

const app = express();
const isLocalHost = ['localhost', '127.0.0.1', '::1'].includes((process.env.PGHOST || '').toLowerCase());

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
  })
);

app.use(express.json());

const pool = new Pool({
  host: process.env.PGHOST,
  port: Number(process.env.PGPORT || 5432),
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  ssl: process.env.PGSSL === 'true' || (!process.env.PGSSL && !isLocalHost) ? { rejectUnauthorized: false } : false,
});

app.get('/', (req, res) => {
  res.json({ success: true, message: 'API is running' });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ success: true, message: 'Server and DB are running' });
  } catch (e) {
    console.error('Health check DB error:', e);
    res.status(500).json({ success: false, message: 'DB not reachable' });
  }
});

app.post('/signup', async (req, res) => {
  try {
    const { username, password, fullName, email, phone, department, college } = req.body;

    if (!username || !password || !fullName || !email || !phone || !department || !college) {
      return res.status(400).json({ success: false, message: 'All signup fields are required' });
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'Username already exists' });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (username, password_hash, role, full_name, email, phone, department, college)
      VALUES ($1, $2, 'user', $3, $4, $5, $6, $7)
      RETURNING id, username, role, full_name, email, phone, department, college
      `,
      [username, hash, fullName, email, phone, department, college]
    );

    const user = result.rows[0];

    return res.status(201).json({
      success: true,
      message: 'User created successfully',
      role: user.role,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        fullName: user.full_name || '',
        email: user.email || '',
        phone: user.phone || '',
        department: user.department || '',
        college: user.college || '',
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    const result = await pool.query(
      `
      SELECT id, username, password_hash, role, full_name, email, phone, department, college
      FROM users
      WHERE username = $1
      `,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    return res.json({
      success: true,
      message: 'Login successful',
      role: user.role || 'user',
      user: {
        id: user.id,
        username: user.username,
        role: user.role || 'user',
        fullName: user.full_name || '',
        email: user.email || '',
        phone: user.phone || '',
        department: user.department || '',
        college: user.college || '',
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, '0.0.0.0', () => {
  console.log('Server running on port ' + PORT);
});