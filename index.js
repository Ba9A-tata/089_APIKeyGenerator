const express = require('express');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const DB_CONFIG = {
  host: 'localhost',
  user: 'root',
  password: 'yogamysql',
  database: 'apikey',
  port: 3308
};

let db;
(async () => {
  try {
    db = await mysql.createPool({ ...DB_CONFIG, waitForConnections: true, connectionLimit: 10 });
    console.log('Connected to MySQL ✅');
  } catch (err) {
    console.error('DB connection error', err);
    process.exit(1);
  }
})();

// session (untuk admin)
app.use(session({
  secret: 'ganti_dengan_secret_random', // ganti untuk production
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 4 } // 4 jam
}));

// static files
app.use('/', express.static(path.join(__dirname, 'public')));

// ----------------- USER endpoints -----------------

app.get('/api/generate-key', (req, res) => {
  try {
    const key = crypto.randomBytes(24).toString('hex');
    return res.json({ success: true, key });
  } catch (e) {
    return res.status(500).json({ success: false, message: 'Gagal generate key' });
  }
});

// save user + api key
app.post('/api/save-user', async (req, res) => {
  const { first_name, last_name, email, key } = req.body;
  if (!first_name || !last_name || !email || !key) {
    return res.status(400).json({ success: false, message: 'Data tidak lengkap' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, message: 'Email tidak valid' });
  }

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    // cek user existing
    const [rows] = await conn.execute('SELECT user_id FROM users WHERE email = ?', [email]);
    let user_id;
    if (rows.length > 0) {
      user_id = rows[0].user_id;
      // update name jika perlu
      await conn.execute('UPDATE users SET first_name = ?, last_name = ?, updated_at = NOW() WHERE user_id = ?', [first_name, last_name, user_id]);
    } else {
      const [ins] = await conn.execute('INSERT INTO users (first_name, last_name, email) VALUES (?, ?, ?)', [first_name, last_name, email]);
      user_id = ins.insertId;
    }

    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 hari
    const expiresSql = expiresAt.toISOString().slice(0, 19).replace('T', ' ');

    await conn.execute('INSERT INTO api_keys (user_id, key_value, out_of_date, status) VALUES (?, ?, ?, ?)', [user_id, key, expiresSql, 'active']);

    await conn.commit();
    return res.json({ success: true });
  } catch (e) {
    await conn.rollback();
    console.error(e);
    return res.status(500).json({ success: false, message: 'Gagal menyimpan data' });
  } finally {
    conn.release();
  }
});

// validate key
app.post('/api/validate-key', async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ valid: false, message: 'No key' });

  const [rows] = await db.execute('SELECT key_id, out_of_date, status FROM api_keys WHERE key_value = ? LIMIT 1', [key]);
  if (rows.length === 0) return res.json({ valid: false, message: 'Key not found' });

  const row = rows[0];
  if (row.status !== 'active') return res.json({ valid: false, message: 'Key not active' });

  if (new Date(row.out_of_date) < new Date()) return res.json({ valid: false, message: 'Key expired' });

  return res.json({ valid: true });
});


