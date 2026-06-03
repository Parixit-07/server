const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const { Pool } = require('pg');

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(helmet());

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);

      if (
        allowedOrigins.length === 0 ||
        allowedOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      return callback(new Error('Not allowed by CORS'));
    },
  })
);

app.use(express.json());

const isLocalHost = ['localhost', '127.0.0.1', '::1'].includes(
  (process.env.PGHOST || '').toLowerCase()
);

const useSsl =
  process.env.PGSSL === 'true' ||
  (!process.env.PGSSL && !isLocalHost);

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
  : new Pool({
      host: process.env.PGHOST,
      port: Number(process.env.PGPORT || 5432),
      user: process.env.PGUSER,
      password: process.env.PGPASSWORD,
      database: process.env.PGDATABASE,
      ssl: useSsl ? { rejectUnauthorized: false } : false,
    });

function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role,
    },
    process.env.JWT_SECRET || 'secretkey',
    {
      expiresIn: '7d',
    }
  );
}

function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized',
      });
    }

    const token = authHeader.split(' ')[1];

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'secretkey'
    );

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid token',
    });
  }
}

function mapEvent(row) {
  return {
    id: row.id,
    name: row.name,
    tagline: row.tagline,
    description: row.description,
    college: row.college,
    department: row.department,
    date: row.event_date,
    location: row.location,
    registrationInfo: row.registration_info,
    registrationLink: row.registration_link,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(50) DEFAULT 'user',
      full_name TEXT,
      phone TEXT,
      department TEXT,
      college TEXT,
      created_at TIMESTAMP DEFAULT now()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      tagline TEXT NOT NULL,
      description TEXT NOT NULL,
      college TEXT NOT NULL,
      department TEXT NOT NULL,
      event_date TIMESTAMP NOT NULL,
      location TEXT NOT NULL,
      registration_info TEXT NOT NULL,
      registration_link TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT now(),
      updated_at TIMESTAMP DEFAULT now()
    )
  `);
}

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'API Running Successfully',
  });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      success: true,
      message: 'Server and Database are healthy',
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: 'Database connection failed',
    });
  }
});

app.post('/signup', async (req, res) => {
  try {
    const {
      username,
      password,
      fullName,
      email,
      phone,
      department,
      college,
    } = req.body;

    if (
      !username ||
      !password ||
      !fullName ||
      !email ||
      !phone ||
      !department ||
      !college
    ) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required',
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters',
      });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Username or email already exists',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (
        username,
        email,
        password_hash,
        full_name,
        phone,
        department,
        college
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
      `,
      [
        username,
        email,
        hashedPassword,
        fullName,
        phone,
        department,
        college,
      ]
    );

    const user = result.rows[0];

    const token = generateToken(user);

    res.status(201).json({
      success: true,
      message: 'Signup successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: 'Server error',
    });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password required',
      });
    }

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE username = $1
      `,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    const token = generateToken(user);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: 'Server error',
    });
  }
});

app.get('/events', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM events
      ORDER BY event_date ASC
    `);

    res.json(result.rows.map(mapEvent));
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: 'Failed to fetch events',
    });
  }
});

app.post('/events', authMiddleware, async (req, res) => {
  try {
    const {
      name,
      tagline,
      description,
      college,
      department,
      date,
      location,
      registrationInfo,
      registrationLink,
    } = req.body;

    if (
      !name ||
      !tagline ||
      !description ||
      !college ||
      !department ||
      !date ||
      !location ||
      !registrationInfo ||
      !registrationLink
    ) {
      return res.status(400).json({
        success: false,
        message: 'All event fields are required',
      });
    }

    const result = await pool.query(
      `
      INSERT INTO events
      (
        name,
        tagline,
        description,
        college,
        department,
        event_date,
        location,
        registration_info,
        registration_link,
        updated_at
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
      RETURNING *
      `,
      [
        name.trim(),
        tagline.trim(),
        description.trim(),
        college.trim(),
        department.trim(),
        new Date(date),
        location.trim(),
        registrationInfo.trim(),
        registrationLink.trim(),
      ]
    );

    res.status(201).json({
      success: true,
      message: 'Event created successfully',
      event: mapEvent(result.rows[0]),
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: 'Failed to create event',
    });
  }
});

app.delete('/events/:id', authMiddleware, async (req, res) => {
  try {
    const id = Number(req.params.id);

    const result = await pool.query(
      'DELETE FROM events WHERE id = $1',
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: 'Event not found',
      });
    }

    res.json({
      success: true,
      message: 'Event deleted successfully',
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: 'Delete failed',
    });
  }
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Startup failed:', error);
    process.exit(1);
  });