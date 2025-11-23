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

