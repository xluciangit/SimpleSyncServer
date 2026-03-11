'use strict';

const express  = require('express');
const multer   = require('multer');
const cors     = require('cors');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const os       = require('os');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const session  = require('express-session');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT       = parseInt(process.env.PORT       || '8080', 10);
const CONFIG_DIR = process.env.CONFIG_DIR          || '/config';
const DATA_DIR   = process.env.DATA_DIR            || '/data';
const DB_PATH    = path.join(CONFIG_DIR, 'sss.db');
const TMP_DIR    = path.join(DATA_DIR, '.tmp');

[CONFIG_DIR, DATA_DIR, TMP_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ── IP blocking + rate limiting ───────────────────────────────────────────────
function getClientIp(req) {
  return req.headers['cf-connecting-ip']
    || req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.ip;
}

function isIpBlocked(ip) {
  return !!db.prepare('SELECT ip FROM blocked_ips WHERE ip = ?').get(ip);
}

function blockIp(ip) {
  db.prepare(`
    INSERT OR IGNORE INTO blocked_ips (ip, blocked_at, reason)
    VALUES (?, datetime('now'), 'Too many failed login attempts')
  `).run(ip);
  console.warn(`[SECURITY] Permanently blocked IP: ${ip}`);
}

function makeRateLimiter({ windowMs, max, message }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) {
      if (now > entry.resetAt) hits.delete(key);
    }
  }, windowMs).unref();

  return function rateLimiter(req, res, next) {
    const ip = getClientIp(req);

    // Check permanent block first
    if (isIpBlocked(ip)) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const now = Date.now();
    let entry = hits.get(ip);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs, violations: entry?.violations || 0 };
      hits.set(ip, entry);
    }
    entry.count++;

    if (entry.count > max) {
      entry.violations++;
      // 3 window violations → permanent block
      if (entry.violations >= 3) {
        blockIp(ip);
        hits.delete(ip);
        return res.status(403).json({ error: 'Access denied.' });
      }
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({ error: message || 'Too many requests, please try again later.' });
    }
    next();
  };
}

// Login: 20 per 5 min — 3 violations → permanent block
const loginLimiter = makeRateLimiter({ windowMs: 5 * 60 * 1000,  max: 20,   message: 'Too many login attempts, please try again in 5 minutes.' });
// API: relaxed — 5000 per 15 min (handles large bulk syncs)
const apiLimiter   = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 5000, message: 'Too many requests, please slow down.' });

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT UNIQUE NOT NULL,
    password_hash        TEXT NOT NULL,
    is_admin             INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    api_key    TEXT UNIQUE NOT NULL,
    label      TEXT NOT NULL DEFAULT 'Default',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS folders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS uploaded_files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    folder_id    INTEGER NOT NULL,
    hash         TEXT NOT NULL,
    filename     TEXT NOT NULL,
    file_size    INTEGER NOT NULL,
    android_path TEXT,
    server_path  TEXT NOT NULL,
    date_folder  TEXT NOT NULL,
    uploaded_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_hash            ON uploaded_files(hash);
  CREATE INDEX IF NOT EXISTS idx_user_folder     ON uploaded_files(user_id, folder_id);
  CREATE INDEX IF NOT EXISTS idx_user_folder_hash ON uploaded_files(user_id, folder_id, hash);

  CREATE TABLE IF NOT EXISTS blocked_ips (
    ip         TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL DEFAULT (datetime('now')),
    reason     TEXT NOT NULL DEFAULT 'Too many failed login attempts'
  );
`);

// Migration: add is_admin column to existing DBs that don't have it yet
try {
  db.exec(`ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`);
} catch (e) { /* column already exists */ }
// Ensure the admin user always has is_admin = 1
db.prepare(`UPDATE users SET is_admin = 1 WHERE username = 'admin'`).run();

// ── Helpers ───────────────────────────────────────────────────────────────────
function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}
function setSetting(key, value) {
  db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)').run(key, value);
}

function generateApiKey() { return crypto.randomBytes(24).toString('hex'); }
function generateSessionSecret() { return crypto.randomBytes(48).toString('hex'); }
function generatePassword() {
  // Readable password – avoids confusing chars (0/O, 1/I/l)
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#';
  return Array.from({ length: 14 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function todayStr(fmt) {
  const d    = new Date();
  const dd   = String(d.getDate()).padStart(2, '0');
  const mm   = String(d.getMonth() + 1).padStart(2, '0');
  const yyyy = d.getFullYear();
  return fmt === 'mdy' ? `${mm}.${dd}.${yyyy}` : `${dd}.${mm}.${yyyy}`;
}

function getUserDateFmt(userId) {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(`datefmt_user_${userId}`);
  return row ? row.value : 'dmy';
}

function setUserDateFmt(userId, fmt) {
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").run(`datefmt_user_${userId}`, fmt);
}

function safeName(n) {
  return typeof n === 'string' && /^[a-zA-Z0-9_\-. ]+$/.test(n) && n.length > 0 && n.length < 64;
}

function fmtBytes(b) {
  if (b < 1024)            return b + ' B';
  if (b < 1_048_576)       return (b / 1024).toFixed(1) + ' KB';
  if (b < 1_073_741_824)   return (b / 1_048_576).toFixed(1) + ' MB';
  return (b / 1_073_741_824).toFixed(2) + ' GB';
}

function folderStats(username, folderName) {
  const base = path.join(DATA_DIR, username, folderName);
  if (!fs.existsSync(base)) return [];
  const dates = fs.readdirSync(base).filter(e => {
    try { return fs.statSync(path.join(base, e)).isDirectory(); } catch { return false; }
  }).sort().reverse();
  return dates.map(date => {
    let count = 0, totalBytes = 0;
    function walk(dir) {
      try {
        for (const e of fs.readdirSync(dir)) {
          const p = path.join(dir, e);
          try {
            const s = fs.statSync(p);
            if (s.isDirectory()) walk(p);
            else { count++; totalBytes += s.size; }
          } catch {}
        }
      } catch {}
    }
    walk(path.join(base, date));
    return { date, count, totalBytes };
  });
}

// ── Bootstrap: first-run admin creation ───────────────────────────────────────
let firstRunPassword = null;
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  firstRunPassword = generatePassword();
  const hash = bcrypt.hashSync(firstRunPassword, 10);
  db.prepare(
    'INSERT INTO users (username, password_hash, is_admin, must_change_password) VALUES (?, ?, 1, 1)'
  ).run('admin', hash);
  // Admin has no API key – it cannot upload files
}

// Session secret: generated once, stored in DB so it survives restarts
let SESSION_SECRET = getSetting('session_secret');
if (!SESSION_SECRET) {
  SESSION_SECRET = generateSessionSecret();
  setSetting('session_secret', SESSION_SECRET);
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1); // Trust Cloudflare / reverse proxy

app.use('/static', express.static(path.join(__dirname, 'static')));
app.use(cors({ origin: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge:   24 * 60 * 60 * 1000,
    httpOnly: true,
    secure:   'auto',  // true via HTTPS/Cloudflare, false on direct http://IP:port
    sameSite: 'lax'
  }
}));

// ── Multer ────────────────────────────────────────────────────────────────────
const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: 20 * 1024 * 1024 * 1024 } // 20 GB
});

// ── Auth middleware ───────────────────────────────────────────────────────────

// Web UI: require session
function requireSession(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  if (req.session.mustChangePassword && req.path !== '/change-password') {
    return res.redirect('/change-password');
  }
  // Admin account can only access /users and /settings (password change)
  if (req.session.isAdmin && !req.path.startsWith('/users') && !req.path.startsWith('/settings') && !req.path.startsWith('/logout')) {
    return res.redirect('/users');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  if (!req.session.isAdmin) return res.status(403).send('Forbidden');
  next();
}

// API: require x-api-key header, attach user to req (admin cannot use API)
function apiAuth(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.apiKey;
  if (!key) return res.status(401).json({ error: 'Missing API key' });
  const row = db.prepare(
    'SELECT ak.user_id, u.username, u.is_admin FROM api_keys ak JOIN users u ON u.id = ak.user_id WHERE ak.api_key = ?'
  ).get(key);
  if (!row) return res.status(401).json({ error: 'Invalid API key' });
  if (row.is_admin) return res.status(403).json({ error: 'Admin account cannot upload files' });
  req.apiUserId   = row.user_id;
  req.apiUsername = row.username;
  next();
}


// ── Theme helpers ─────────────────────────────────────────────────────────────
function getUserTheme(userId) {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(`theme_user_${userId}`);
  return row ? row.value : 'dark';
}
function setUserTheme(userId, theme) {
  db.prepare("INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)").run(`theme_user_${userId}`, theme);
}

// ── Web UI routes ─────────────────────────────────────────────────────────────

app.get('/', requireSession, (req, res) => {
  if (req.session.isAdmin) return res.redirect('/users');
  const user    = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId);
  const apiKeyRow = db.prepare('SELECT api_key, label FROM api_keys WHERE user_id = ? LIMIT 1').get(user.id);
  const folders = db.prepare('SELECT * FROM folders WHERE user_id = ? ORDER BY name ASC').all(user.id);
  const foldersWithStats = folders.map(f => ({
    ...f,
    stats: folderStats(user.username, f.name)
  }));

  let totalFiles = 0, totalBytes = 0;
  foldersWithStats.forEach(f => f.stats.forEach(s => { totalFiles += s.count; totalBytes += s.totalBytes; }));

  const up = Math.floor(os.uptime());
  const hh = Math.floor(up / 3600), mm = Math.floor((up % 3600) / 60);

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  const theme = req.session.theme || 'dark';
  res.send(renderDashboard({
    username: user.username,
    apiKey: apiKeyRow ? apiKeyRow.api_key : null,
    apiKeyLabel: apiKeyRow ? apiKeyRow.label : 'Default',
    folders: foldersWithStats,
    totalFiles,
    totalBytes: fmtBytes(totalBytes),
    uptime: `${hh}h ${mm}m`,
    theme
  }));
});

app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderLogin({ error: null }));
});

app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send(renderLogin({ error: 'Username and password are required' }));
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.send(renderLogin({ error: 'Invalid username or password' }));
  }
  req.session.userId             = user.id;
  req.session.username           = user.username;
  req.session.isAdmin            = user.is_admin === 1;
  req.session.mustChangePassword = user.must_change_password === 1;
  req.session.theme              = getUserTheme(user.id);
  if (user.must_change_password) return res.redirect('/change-password');
  if (user.is_admin) return res.redirect('/users');
  res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/change-password', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderChangePassword({ error: null, isFirstTime: req.session.mustChangePassword }));
});

app.post('/change-password', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const { new_password, confirm_password } = req.body;
  if (!new_password || new_password.length < 8) {
    return res.send(renderChangePassword({ error: 'Password must be at least 8 characters', isFirstTime: req.session.mustChangePassword }));
  }
  if (new_password !== confirm_password) {
    return res.send(renderChangePassword({ error: 'Passwords do not match', isFirstTime: req.session.mustChangePassword }));
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?')
    .run(hash, req.session.userId);
  req.session.mustChangePassword = false;
  res.redirect('/');
});

app.get('/settings', requireSession, (req, res) => {
  const user      = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId);
  const apiKeyRow = db.prepare('SELECT api_key, label FROM api_keys WHERE user_id = ? LIMIT 1').get(user.id);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderSettings({
    username: user.username,
    apiKey: apiKeyRow ? apiKeyRow.api_key : null,
    apiKeyLabel: apiKeyRow ? apiKeyRow.label : 'Default',
    error: null, success: null,
    theme: req.session.theme || 'dark',
    isAdmin: req.session.isAdmin || false,
    dateFmt: req.session.dateFmt || 'dmy',
    localUrl: getSetting('local_url') || null
  }));
});

app.post('/settings/password', requireSession, (req, res) => {
  const { current_password, new_password, confirm_password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!bcrypt.compareSync(current_password || '', user.password_hash)) {
    return respondSettings(req, res, 'Current password is incorrect', null);
  }
  if (!new_password || new_password.length < 8) {
    return respondSettings(req, res, 'New password must be at least 8 characters', null);
  }
  if (new_password !== confirm_password) {
    return respondSettings(req, res, 'New passwords do not match', null);
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.session.userId);
  respondSettings(req, res, null, 'Password updated successfully');
});

app.post('/settings/theme', requireSession, (req, res) => {
  const { theme } = req.body;
  if (!['dark', 'light'].includes(theme)) return res.redirect('/settings');
  setUserTheme(req.session.userId, theme);
  req.session.theme = theme;
  res.redirect('/settings');
});

app.post('/settings/regen-key', requireSession, (req, res) => {
  const newKey = generateApiKey();
  const existing = db.prepare('SELECT id FROM api_keys WHERE user_id = ?').get(req.session.userId);
  if (existing) {
    db.prepare('UPDATE api_keys SET api_key = ? WHERE user_id = ?').run(newKey, req.session.userId);
  } else {
    db.prepare('INSERT INTO api_keys (user_id, api_key, label) VALUES (?,?,?)').run(req.session.userId, newKey, 'Default');
  }
  respondSettings(req, res, null, 'API key regenerated');
});

app.post('/settings/dateformat', requireSession, (req, res) => {
  const { date_format } = req.body;
  if (!['dmy', 'mdy'].includes(date_format)) return res.redirect('/settings');
  setUserDateFmt(req.session.userId, date_format);
  req.session.dateFmt = date_format;
  respondSettings(req, res, null, 'Date format updated.');
});

app.post('/settings/local-url', requireAdmin, (req, res) => {
  const raw = (req.body.local_url || '').trim();
  if (raw && !raw.match(/^https?:\/\/.+/)) {
    return respondSettings(req, res, 'Invalid URL — must start with http:// or https://', null);
  }
  setSetting('local_url', raw);
  respondSettings(req, res, null, raw ? `Local URL saved: ${raw}` : 'Local URL cleared.');
});

function respondSettings(req, res, error, success) {
  const user      = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId);
  const apiKeyRow = db.prepare('SELECT api_key, label FROM api_keys WHERE user_id = ? LIMIT 1').get(user.id);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderSettings({
    username: user.username,
    apiKey: apiKeyRow ? apiKeyRow.api_key : null,
    apiKeyLabel: apiKeyRow ? apiKeyRow.label : 'Default',
    error, success,
    theme: req.session.theme || 'dark',
    isAdmin: req.session.isAdmin || false,
    dateFmt: req.session.dateFmt || 'dmy',
    localUrl: getSetting('local_url') || null
  }));
}

// ── Web UI folder management ──────────────────────────────────────────────────

app.post('/web/folders/add', requireSession, (req, res) => {
  const { name } = req.body;
  if (!safeName(name)) return res.redirect('/?err=' + encodeURIComponent('Invalid folder name'));
  try {
    const result = db.prepare('INSERT INTO folders (user_id, name) VALUES (?, ?)').run(req.session.userId, name.trim());
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.session.userId);
    fs.mkdirSync(path.join(DATA_DIR, user.username, name.trim()), { recursive: true });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.redirect('/?err=' + encodeURIComponent('Folder already exists'));
  }
  res.redirect('/');
});

app.post('/web/folders/delete', requireSession, (req, res) => {
  const { name } = req.body;
  db.prepare('DELETE FROM folders WHERE user_id = ? AND name = ?').run(req.session.userId, name);
  res.redirect('/');
});

// ── Admin: Blocked IPs ────────────────────────────────────────────────────────

app.post('/users/unblock', requireAdmin, (req, res) => {
  const { ip } = req.body;
  const theme  = req.session.theme || 'dark';
  const users  = () => db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
  const blocked = () => db.prepare('SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC').all();

  if (!ip) return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Missing IP.', success: null }));
  db.prepare('DELETE FROM blocked_ips WHERE ip = ?').run(ip);
  console.log(`[SECURITY] Admin unblocked IP: ${ip}`);
  return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: null, success: `IP ${ip} has been unblocked.` }));
});

// ── Admin: User Management ────────────────────────────────────────────────────

app.get('/users', requireAdmin, (req, res) => {
  const users   = db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
  const blocked = db.prepare('SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC').all();
  const theme   = req.session.theme || 'dark';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderUsersPage({ users, blocked, theme, error: null, success: null }));
});

app.post('/users/create', requireAdmin, (req, res) => {
  const { username, password, confirm_password } = req.body;
  const theme   = req.session.theme || 'dark';
  const users   = () => db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
  const blocked = () => db.prepare('SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC').all();

  if (!username || !safeName(username)) {
    return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Invalid username. Use letters, numbers, dash, underscore or dot.', success: null }));
  }
  if (!password || password.length < 8) {
    return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Password must be at least 8 characters.', success: null }));
  }
  if (password !== confirm_password) {
    return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Passwords do not match.', success: null }));
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
  if (existing) {
    return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Username already taken.', success: null }));
  }
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare(
    'INSERT INTO users (username, password_hash, is_admin, must_change_password) VALUES (?, ?, 0, 0)'
  ).run(username.trim(), hash);
  const apiKey = generateApiKey();
  db.prepare('INSERT INTO api_keys (user_id, api_key, label) VALUES (?, ?, ?)').run(result.lastInsertRowid, apiKey, 'Default');
  return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: null, success: `User "${username.trim()}" created successfully.` }));
});

app.post('/users/delete', requireAdmin, (req, res) => {
  const { user_id } = req.body;
  const theme   = req.session.theme || 'dark';
  const users   = () => db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
  const blocked = () => db.prepare('SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC').all();

  if (!user_id) return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Missing user ID.', success: null }));
  const target = db.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').get(parseInt(user_id));
  if (!target) return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'User not found.', success: null }));
  if (target.is_admin) return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Cannot delete the admin account.', success: null }));

  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: null, success: `User "${target.username}" deleted.` }));
});

app.post('/users/change-password', requireAdmin, (req, res) => {
  const { user_id, new_password, confirm_password } = req.body;
  const theme   = req.session.theme || 'dark';
  const users   = () => db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
  const blocked = () => db.prepare('SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC').all();

  const target = db.prepare('SELECT id, username FROM users WHERE id = ?').get(parseInt(user_id));
  if (!target) return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'User not found.', success: null }));
  if (!new_password || new_password.length < 8) {
    return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Password must be at least 8 characters.', success: null }));
  }
  if (new_password !== confirm_password) {
    return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: 'Passwords do not match.', success: null }));
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, target.id);
  return res.send(renderUsersPage({ users: users(), blocked: blocked(), theme, error: null, success: `Password for "${target.username}" updated.` }));
});

// ── API ───────────────────────────────────────────────────────────────────────

// Health check (no auth)
app.get('/api/ping', (req, res) => res.json({ ok: true, version: '1.0.0', app: 'Simple Sync Server' }));

// Returns both URLs so the Android app can discover the LAN endpoint
app.get('/api/config', apiAuth, (req, res) => {
  const localUrl = getSetting('local_url') || null;
  res.json({ local_url: localUrl });
});

// Check if a file hash already exists for this user+folder
app.post('/api/check-hash', apiLimiter, apiAuth, (req, res) => {
  const { hash, folder } = req.body;
  if (!hash || !folder) return res.status(400).json({ error: 'Missing hash or folder' });

  const folderRow = db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ?')
    .get(req.apiUserId, folder);

  if (!folderRow) {
    // Folder doesn't exist yet — file definitely not uploaded, client will upload and auto-create
    return res.json({ exists: false });
  }

  const row = db.prepare(
    'SELECT id FROM uploaded_files WHERE user_id = ? AND folder_id = ? AND hash = ? LIMIT 1'
  ).get(req.apiUserId, folderRow.id, hash);

  res.json({ exists: !!row });
});

// Upload a file
app.post('/api/upload', apiLimiter, apiAuth, upload.single('file'), (req, res) => {
  const { folder, relative_path, hash, android_path } = req.body;
  const file = req.file;

  if (!file) return res.status(400).json({ error: 'No file' });
  if (!folder || !relative_path) {
    fs.unlinkSync(file.path);
    return res.status(400).json({ error: 'Missing folder or relative_path' });
  }

  const username = req.apiUsername;
  const fmt      = getUserDateFmt(req.apiUserId);
  const date     = todayStr(fmt);

  // ── Path traversal guard ──────────────────────────────────────────────────
  const safeRelative = path.normalize(relative_path).replace(/^(\.\.[/\\])+/, '');
  const userRoot     = path.resolve(DATA_DIR, username);
  const destFile     = path.resolve(userRoot, folder, date, safeRelative);
  const destDir      = path.dirname(destFile);
  if (!destFile.startsWith(userRoot + path.sep)) {
    try { fs.unlinkSync(file.path); } catch {}
    return res.status(400).json({ error: 'Invalid file path' });
  }
  // ─────────────────────────────────────────────────────────────────────────

  try {
    fs.mkdirSync(destDir, { recursive: true });
    fs.renameSync(file.path, destFile);
  } catch (e) {
    try { fs.unlinkSync(file.path); } catch {}
    return res.status(500).json({ error: String(e) });
  }

  // Ensure folder exists in DB (auto-create on first upload)
  let folderRow = db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ?')
    .get(req.apiUserId, folder);
  if (!folderRow) {
    const r = db.prepare('INSERT OR IGNORE INTO folders (user_id, name) VALUES (?, ?)').run(req.apiUserId, folder);
    folderRow = { id: r.lastInsertRowid } ||
      db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ?').get(req.apiUserId, folder);
  }

  // Insert into uploaded_files
  db.prepare(`
    INSERT INTO uploaded_files (user_id, folder_id, hash, filename, file_size, android_path, server_path, date_folder)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    req.apiUserId,
    folderRow.id,
    hash || '',
    path.basename(safeRelative),
    file.size,
    android_path || relative_path,
    path.join(username, folder, date, safeRelative),
    date
  );

  res.json({ ok: true, stored: path.join(username, folder, date, safeRelative) });
});

// List folders for API user
app.get('/api/folders', apiAuth, (req, res) => {
  const user    = db.prepare('SELECT username FROM users WHERE id = ?').get(req.apiUserId);
  const folders = db.prepare('SELECT * FROM folders WHERE user_id = ? ORDER BY name ASC').all(req.apiUserId);
  res.json(folders.map(f => ({ ...f, stats: folderStats(user.username, f.name) })));
});

// Add folder via API
app.post('/api/folders', apiAuth, (req, res) => {
  const { name } = req.body;
  if (!safeName(name)) return res.status(400).json({ error: 'Invalid folder name' });
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.apiUserId);
  try {
    db.prepare('INSERT INTO folders (user_id, name) VALUES (?, ?)').run(req.apiUserId, name.trim());
    fs.mkdirSync(path.join(DATA_DIR, user.username, name.trim()), { recursive: true });
    res.json({ ok: true });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Folder already exists' });
    res.status(500).json({ error: String(e) });
  }
});

// Stats summary
app.get('/api/stats', apiAuth, (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as n, SUM(file_size) as total FROM uploaded_files WHERE user_id = ?').get(req.apiUserId);
  res.json({
    folders: db.prepare('SELECT COUNT(*) as n FROM folders WHERE user_id = ?').get(req.apiUserId).n,
    totalFiles: count.n || 0,
    totalBytes: fmtBytes(count.total || 0),
    uptime: Math.floor(os.uptime())
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  const border = '═'.repeat(46);
  console.log(`╔${border}╗`);
  console.log(`║         Simple Sync Server v1.0.0              ║`);
  console.log(`╚${border}╝`);
  console.log(`  Port:    ${PORT}`);
  console.log(`  Data:    ${DATA_DIR}`);
  console.log(`  Config:  ${CONFIG_DIR}`);
  if (firstRunPassword) {
    const b = '─'.repeat(44);
    console.log(`\n  ┌${b}┐`);
    console.log(`  │  FIRST RUN – Admin credentials created:      │`);
    console.log(`  │  Username : admin                            │`);
    console.log(`  │  Password : ${firstRunPassword.padEnd(32)} │`);
    console.log(`  │                                              │`);
    console.log(`  │  You will be asked to change the password    │`);
    console.log(`  │  on first login.                             │`);
    console.log(`  │  Admin account is for user management only.  │`);
    console.log(`  └${b}┘\n`);
  }
  console.log(`  Web UI:   http://localhost:${PORT}\n`);
});

// ── HTML Templates ─────────────────────────────────────────────────────────────


const FAVICON_TAG = `<link rel="icon" type="image/png" href="/static/favicon.png">`;

const BASE_STYLE = `
  *{box-sizing:border-box;margin:0;padding:0}
  /* ── Dark theme (default) ───────────────────────── */
  :root{
    --bg:#0f1117;--surface:#1a1d27;--surface2:#22263a;
    --border:#2e3248;--accent:#5b9cf6;--accent2:#4ade80;
    --red:#f87171;--yellow:#facc15;
    --text:#e2e8f0;--muted:#64748b;--radius:10px;
    --input-bg:#0f1117;--btn-primary-text:#0f1117;
    --card-shadow:none;
  }
  /* ── Light theme ──────────────────────────────────── */
  [data-theme="light"]{
    --bg:#f0f4f8;--surface:#ffffff;--surface2:#e8eef5;
    --border:#c8d5e3;--accent:#2563eb;--accent2:#16a34a;
    --red:#dc2626;--yellow:#d97706;
    --text:#1e293b;--muted:#64748b;--radius:10px;
    --input-bg:#ffffff;--btn-primary-text:#ffffff;
    --card-shadow:0 1px 4px rgba(0,0,0,.08);
  }
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
  a{color:var(--accent);text-decoration:none}
  .hdr{background:var(--surface);border-bottom:1px solid var(--border);padding:8px 14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-height:56px}
  .hdr .logo{font-size:1.05rem;font-weight:700;color:var(--accent);display:flex;align-items:center;gap:8px}
  .hdr .logo img{width:26px;height:26px}
  .hdr .badge{background:var(--surface2);border:1px solid var(--border);padding:3px 8px;border-radius:20px;font-size:.72rem;color:var(--muted)}
  .hdr .ml{margin-left:auto;display:flex;align-items:center;gap:6px;flex-wrap:nowrap}
  @media(max-width:540px){.hdr-hide{display:none!important}}
  .wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px;box-shadow:var(--card-shadow)}
  .card h2{font-size:1rem;font-weight:600;color:var(--accent);margin-bottom:16px}
  .btn{cursor:pointer;border:none;border-radius:8px;padding:9px 18px;font-size:.85rem;font-weight:600;transition:.15s;display:inline-block}
  .btn-primary{background:var(--accent);color:var(--btn-primary-text)}.btn-primary:hover{opacity:.85}
  .btn-ghost{background:var(--surface2);color:var(--text);border:1px solid var(--border)}.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
  .btn-red{background:rgba(248,113,113,.15);color:var(--red);border:1px solid rgba(248,113,113,.3)}.btn-red:hover{background:rgba(248,113,113,.25)}
  .btn-sm{padding:5px 12px;font-size:.78rem}
  .form-group{margin-bottom:14px}
  .form-group label{display:block;font-size:.82rem;color:var(--muted);margin-bottom:6px}
  input[type=text],input[type=password],input[type=url]{background:var(--input-bg);border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text);font-size:.9rem;width:100%;outline:none;transition:.15s}
  input[type=text]:focus,input[type=password]:focus,input[type=url]:focus{border-color:var(--accent)}
  .err{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.4);border-radius:8px;padding:10px 14px;color:var(--red);font-size:.85rem;margin-bottom:14px}
  .ok{background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.4);border-radius:8px;padding:10px 14px;color:var(--accent2);font-size:.85rem;margin-bottom:14px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
  @media(max-width:720px){.grid2{grid-template-columns:1fr}}
  .stats-row{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
  .stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;flex:1;min-width:140px;box-shadow:var(--card-shadow)}
  .stat .val{font-size:1.8rem;font-weight:700;color:var(--accent)}
  .stat .lbl{font-size:.78rem;color:var(--muted);margin-top:4px}
  .key-row{display:flex;align-items:center;gap:8px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:11px 14px;margin-bottom:12px}
  .key-val{font-family:monospace;font-size:.83rem;color:var(--accent2);word-break:break-all;flex:1}
  .folder-item{border:1px solid var(--border);border-radius:8px;margin-bottom:10px;overflow:hidden;box-shadow:var(--card-shadow)}
  .folder-hdr{display:flex;align-items:center;gap:12px;padding:12px 16px;background:var(--surface2);cursor:pointer;user-select:none}
  .folder-hdr:hover{filter:brightness(1.05)}
  .folder-body{padding:14px 16px;display:none;background:var(--surface)}
  .folder-body.open{display:block}
  .date-row{display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);font-size:.85rem}
  .date-row:last-child{border-bottom:none}
  .date-tag{background:rgba(91,156,246,.12);color:var(--accent);border-radius:6px;padding:2px 10px;font-size:.78rem;min-width:90px;text-align:center}
  .section-title{font-size:1rem;font-weight:700;color:var(--text);margin:22px 0 12px}
  .warn{background:rgba(250,204,21,.08);border:1px solid rgba(250,204,21,.3);border-radius:8px;padding:10px 14px;font-size:.82rem;color:var(--yellow);margin-bottom:14px}
  .form-row{display:flex;gap:8px;margin-top:4px}
  .form-row input{flex:1}
  /* Theme toggle pill */
  .theme-pill{display:flex;background:var(--surface2);border:1px solid var(--border);border-radius:24px;padding:3px;gap:2px}
  .theme-pill button{background:none;border:none;border-radius:20px;padding:5px 14px;font-size:.8rem;font-weight:600;cursor:pointer;color:var(--muted);transition:.15s}
  .theme-pill button.active{background:var(--accent);color:var(--btn-primary-text)}
  #toast{position:fixed;bottom:24px;right:24px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 20px;color:var(--text);font-size:.9rem;opacity:0;pointer-events:none;transition:opacity .3s;z-index:999;max-width:320px;box-shadow:var(--card-shadow)}
  #toast.show{opacity:1}
`;

const LOGO_SVG = `<img src="/static/favicon.png" style="width:36px;height:36px;object-fit:contain;border-radius:6px" alt="SSS">`;

function renderLogin({ error }) {
  return `<!DOCTYPE html><html lang="en" data-theme="dark"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login – Simple Sync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}
  .login-wrap{display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}
  .login-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:36px 32px;width:100%;max-width:400px}
  .login-logo{display:flex;align-items:center;gap:10px;margin-bottom:6px}
  .login-logo svg{width:32px;height:32px;color:var(--accent)}
  .login-logo span{font-size:1.3rem;font-weight:700;color:var(--accent)}
  .login-sub{color:var(--muted);font-size:.85rem;margin-bottom:28px}
</style></head><body>
<div class="login-wrap"><div class="login-card">
  <div class="login-logo">${LOGO_SVG}<span>Simple Sync Server</span></div>
  <p class="login-sub">Sign in to manage your sync server</p>
  ${error ? `<div class="err">${error}</div>` : ''}
  <form method="POST" action="/login">
    <div class="form-group"><label>Username</label>
      <input type="text" name="username" autofocus autocomplete="username" required></div>
    <div class="form-group"><label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required></div>
    <button class="btn btn-primary" style="width:100%;margin-top:8px" type="submit">Sign In</button>
  </form>
</div></div>
</body></html>`;
}

function renderChangePassword({ error, isFirstTime }) {
  return `<!DOCTYPE html><html lang="en" data-theme="dark"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Change Password – Simple Sync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}
  .login-wrap{display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}
  .login-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:36px 32px;width:100%;max-width:420px}
</style></head><body>
<div class="login-wrap"><div class="login-card">
  <h2 style="color:var(--accent);margin-bottom:8px">${isFirstTime ? '👋 Welcome! Please set a new password' : 'Change Password'}</h2>
  ${isFirstTime ? '<p style="color:var(--muted);font-size:.85rem;margin-bottom:20px">Your account was created with a temporary password. Please set a secure password before continuing.</p>' : ''}
  ${error ? `<div class="err">${error}</div>` : ''}
  <form method="POST" action="/change-password">
    <div class="form-group"><label>New Password (min 8 characters)</label>
      <input type="password" name="new_password" autofocus required></div>
    <div class="form-group"><label>Confirm New Password</label>
      <input type="password" name="confirm_password" required></div>
    <button class="btn btn-primary" style="width:100%;margin-top:8px" type="submit">Set Password</button>
  </form>
</div></div>
</body></html>`;
}

function renderDashboard({ username, apiKey, apiKeyLabel, folders, totalFiles, totalBytes, uptime, theme = 'dark' }) {
  const folderRows = folders.length === 0
    ? '<p style="color:var(--muted);padding:12px 0">No folders yet. Add one below.</p>'
    : folders.map(f => {
        const stats = f.stats || [];
        const tFiles = stats.reduce((a, s) => a + s.count, 0);
        const tBytes = stats.reduce((a, s) => a + s.totalBytes, 0);
        const rows = stats.length === 0
          ? '<p style="color:var(--muted);font-size:.85rem">No uploads yet</p>'
          : stats.map(s => `<div class="date-row">
              <span class="date-tag">${s.date}</span>
              <span style="color:var(--muted);flex:1">${s.count} file${s.count !== 1 ? 's' : ''}</span>
              <span style="color:var(--accent2)">${fmtBytes(s.totalBytes)}</span>
            </div>`).join('');
        return `<div class="folder-item">
          <div class="folder-hdr" onclick="tog('${f.name}')">
            <span>📁</span>
            <span style="font-weight:600;flex:1">${f.name}</span>
            <span style="color:var(--muted);font-size:.82rem">${tFiles} files · ${fmtBytes(tBytes)}</span>
            <span style="color:var(--muted);margin-left:8px">▾</span>
          </div>
          <div class="folder-body" id="fb-${f.name}">
            ${rows}
            <div style="margin-top:12px">
              <button class="btn btn-red btn-sm" onclick="showRemoveModal('${f.name}')">Remove Config</button>
              <span style="font-size:.75rem;color:var(--muted);margin-left:10px">Data on disk is kept</span>
            </div>
          </div>
        </div>`;
      }).join('');

  return `<!DOCTYPE html><html lang="en" data-theme="${theme}"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Simple Sync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}</style></head><body>
<div class="hdr">
  <div class="logo">${LOGO_SVG} Simple Sync Server</div>
  <span class="badge hdr-hide">v1.0.0</span>
  <span class="badge hdr-hide">⏱ ${uptime}</span>
  <div class="ml">
    <span class="hdr-hide" style="color:var(--muted);font-size:.85rem">👤 ${username}</span>
    <a href="/settings" class="btn btn-ghost btn-sm">Settings</a>
    <div class="theme-pill">
      <button onclick="setTheme('dark')" class="${theme==='dark'?'active':''}" id="hbtn-dark">🌙</button>
      <button onclick="setTheme('light')" class="${theme==='light'?'active':''}" id="hbtn-light">☀️</button>
    </div>
    <form method="POST" action="/logout" style="display:inline">
      <button class="btn btn-ghost btn-sm" type="submit">Sign Out</button>
    </form>
  </div>
</div>
<div class="wrap">
  <div class="stats-row">
    <div class="stat"><div class="val">${folders.length}</div><div class="lbl">Configured Folders</div></div>
    <div class="stat"><div class="val">${totalFiles.toLocaleString()}</div><div class="lbl">Total Files Received</div></div>
    <div class="stat"><div class="val">${totalBytes}</div><div class="lbl">Total Data Stored</div></div>
  </div>
  <div class="grid2">
    <div class="card">
      <h2>🔑 API Key</h2>
      <div class="warn">⚠ Enter this key in Simple Sync Companion to authorise uploads.</div>
      <div class="key-row">
        <span class="key-val" id="kv">${apiKey || 'No key – go to Settings'}</span>
        <button class="btn btn-ghost btn-sm" onclick="copyKey()">Copy</button>
      </div>
      <a href="/settings" class="btn btn-ghost btn-sm">Manage in Settings →</a>
    </div>
    <div class="card">
      <h2>📁 Add Sync Folder</h2>
      <p style="font-size:.85rem;color:var(--muted);margin-bottom:14px">Folders are created automatically when the app uploads. You can also pre-create them here.</p>
      <form method="POST" action="/web/folders/add">
        <div class="form-row">
          <input type="text" name="name" placeholder="e.g. Photos" maxlength="63">
          <button class="btn btn-primary" type="submit">Add</button>
        </div>
      </form>
    </div>
  </div>
  <div class="section-title">📂 Sync Folders</div>
  <div id="folders-list">${folderRows}</div>
</div>
<div id="toast"></div>
<!-- Remove folder confirmation modal -->
<div id="removeModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;align-items:center;justify-content:center">
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:28px 24px;max-width:380px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.4)">
    <div style="font-size:1.1rem;font-weight:600;margin-bottom:8px">Remove Folder Config?</div>
    <div style="color:var(--muted);font-size:.9rem;margin-bottom:20px">The folder config will be removed from the server. <strong style="color:var(--text)">Files on disk are not deleted.</strong></div>
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" onclick="hideRemoveModal()">Cancel</button>
      <form id="removeForm" method="POST" action="/web/folders/delete" style="display:inline">
        <input type="hidden" id="removeNameInput" name="name" value="">
        <button class="btn btn-red btn-sm" type="submit">Yes, Remove</button>
      </form>
    </div>
  </div>
</div>
<script>
function showRemoveModal(name){
  document.getElementById('removeNameInput').value=name;
  const m=document.getElementById('removeModal');
  m.style.display='flex';
  m.onclick=function(e){if(e.target===m)hideRemoveModal()};
}
function hideRemoveModal(){document.getElementById('removeModal').style.display='none';}
function tog(n){const el=document.getElementById('fb-'+n);el.classList.toggle('open')}
function copyKey(){const v=document.getElementById('kv').textContent;navigator.clipboard.writeText(v).then(()=>toast('API key copied!')).catch(()=>toast('Could not copy'))}
function toast(m){const el=document.getElementById('toast');el.textContent=m;el.className='show';clearTimeout(el._t);el._t=setTimeout(()=>el.className='',3000)}
function setTheme(t){
  document.documentElement.setAttribute('data-theme',t);
  ['dark','light'].forEach(x=>{
    const b=document.getElementById('hbtn-'+x);
    if(b) b.className = x===t?'active':'';
  });
  fetch('/settings/theme',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'theme='+t});
}
</script>
</body></html>`;
}

function renderSettings({ username, apiKey, apiKeyLabel, error, success, theme = 'dark', isAdmin = false, dateFmt = 'dmy', localUrl = null }) {
  return `<!DOCTYPE html><html lang="en" data-theme="${theme}"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Settings – Simple Sync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}
  .section{margin-bottom:28px}
  .section h3{font-size:.95rem;font-weight:600;color:var(--text);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border)}
</style></head><body>
<div class="hdr">
  <div class="logo">${LOGO_SVG} Simple Sync Server</div>
  <div class="ml">
    <a href="${isAdmin ? '/users' : '/'}" class="btn btn-ghost btn-sm">← ${isAdmin ? 'User Management' : 'Dashboard'}</a>
    <form method="POST" action="/logout" style="display:inline">
      <button class="btn btn-ghost btn-sm" type="submit">Sign Out</button>
    </form>
  </div>
</div>
<div class="wrap" style="max-width:620px">
  <h2 style="margin-bottom:22px;color:var(--text)">⚙ Settings</h2>
  ${error ? `<div class="err">${error}</div>` : ''}
  ${success ? `<div class="ok">✓ ${success}</div>` : ''}

  <div class="card section">
    <h3>👤 Account</h3>
    <div class="form-group">
      <label>Username</label>
      <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--muted);font-size:.9rem">${username}</div>
      <p style="font-size:.78rem;color:var(--muted);margin-top:6px">Username cannot be changed after account creation.</p>
    </div>
  </div>

  <div class="card section">
    <h3>🔒 Change Password</h3>
    <form method="POST" action="/settings/password">
      <div class="form-group"><label>Current Password</label>
        <input type="password" name="current_password"></div>
      <div class="form-group"><label>New Password</label>
        <input type="password" name="new_password"></div>
      <div class="form-group"><label>Confirm New Password</label>
        <input type="password" name="confirm_password"></div>
      <button class="btn btn-primary btn-sm" type="submit">Change Password</button>
    </form>
  </div>

  ${!isAdmin ? `
  <div class="card section">
    <h3>🔑 API Key</h3>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:12px">Use this key in Simple Sync Companion.</p>
    <div class="key-row">
      <span class="key-val" id="kv">${apiKey || 'No key yet'}</span>
      <button class="btn btn-ghost btn-sm" onclick="copyKey()">Copy</button>
    </div>
    <button class="btn btn-red btn-sm" onclick="showRegenModal()">Regenerate Key</button>
    <div id="regenModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;align-items:center;justify-content:center">
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:28px 24px;max-width:380px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.4)">
        <div style="font-size:1.1rem;font-weight:600;margin-bottom:8px">Regenerate API Key?</div>
        <div style="color:var(--muted);font-size:.9rem;margin-bottom:20px">A new key will be generated. <strong style="color:var(--text)">You will need to update the Android app with the new key.</strong></div>
        <div style="display:flex;gap:10px;justify-content:flex-end">
          <button class="btn btn-ghost btn-sm" onclick="hideRegenModal()">Cancel</button>
          <form method="POST" action="/settings/regen-key" style="display:inline">
            <button class="btn btn-red btn-sm" type="submit">Yes, Regenerate</button>
          </form>
        </div>
      </div>
    </div>
  </div>

  <div class="card section">
    <h3>📅 Folder Date Format</h3>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Sets the subfolder name used when files sync. Today: <strong id="dateSample" style="color:var(--accent2)"></strong></p>
    <form method="POST" action="/settings/dateformat">
      <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:14px">
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:.9rem">
          <input type="radio" name="date_format" value="dmy" ${dateFmt==='dmy'?'checked':''} onchange="updateSample(this.value)">
          <span>DD.MM.YYYY <span style="color:var(--muted);font-size:.8rem">(e.g. 24.03.2025)</span></span>
        </label>
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:.9rem">
          <input type="radio" name="date_format" value="mdy" ${dateFmt==='mdy'?'checked':''} onchange="updateSample(this.value)">
          <span>MM.DD.YYYY <span style="color:var(--muted);font-size:.8rem">(e.g. 03.24.2025)</span></span>
        </label>
      </div>
      <button class="btn btn-primary btn-sm" type="submit">Save</button>
    </form>
  </div>

  <div class="card section">
    <h3>🎨 Appearance</h3>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Choose the colour scheme for the web interface.</p>
    <div class="theme-pill">
      <button onclick="setTheme('dark')" class="${theme==='dark'?'active':''}" id="btn-dark">🌙 Dark</button>
      <button onclick="setTheme('light')" class="${theme==='light'?'active':''}" id="btn-light">☀️ Light</button>
    </div>
  </div>
  ` : `
  <div class="card section">
    <h3>🏠 Local Network URL</h3>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Direct LAN/IP address for the Android app to use when on your home network. Bypasses Cloudflare's 100 MB limit — required for large files.</p>
    <form method="POST" action="/settings/local-url">
      <div class="form-group" style="margin-bottom:12px">
        <input type="url" name="local_url" value="${localUrl || ''}" placeholder="e.g. http://192.168.1.100:8080" style="width:100%;box-sizing:border-box" autocomplete="off" spellcheck="false">
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <button class="btn btn-primary btn-sm" type="submit">Save</button>
        ${localUrl ? `<button class="btn btn-ghost btn-sm" type="submit" name="local_url" value="">Clear</button>` : ''}
      </div>
    </form>
    ${localUrl ? `<p style="color:var(--muted);font-size:.8rem;margin-top:10px">App will try LAN first, fall back to tunnel if unreachable.</p>` : ''}
  </div>

  <div class="card section">
    <h3>🎨 Appearance</h3>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Choose the colour scheme for the web interface.</p>
    <div class="theme-pill">
      <button onclick="setTheme('dark')" class="${theme==='dark'?'active':''}" id="btn-dark">🌙 Dark</button>
      <button onclick="setTheme('light')" class="${theme==='light'?'active':''}" id="btn-light">☀️ Light</button>
    </div>
  </div>
  `}
</div>
<div id="toast"></div>
<script>
function copyKey(){const v=document.getElementById('kv').textContent;navigator.clipboard.writeText(v).then(()=>toast('Copied!')).catch(()=>toast('Could not copy'))}
function toast(m){const el=document.getElementById('toast');el.textContent=m;el.className='show';clearTimeout(el._t);el._t=setTimeout(()=>el.className='',3000)}
function setTheme(t){
  // Apply immediately for instant feedback
  document.documentElement.setAttribute('data-theme', t);
  document.getElementById('btn-dark').className  = t==='dark'  ? 'active' : '';
  document.getElementById('btn-light').className = t==='light' ? 'active' : '';
  // Persist server-side
  fetch('/settings/theme', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'theme='+t});
}
function showRegenModal(){const m=document.getElementById('regenModal');m.style.display='flex';m.onclick=function(e){if(e.target===m)hideRegenModal()};}
function hideRegenModal(){document.getElementById('regenModal').style.display='none';}
function updateSample(fmt){
  const el=document.getElementById('dateSample'); if(!el)return;
  const now=new Date(), dd=String(now.getDate()).padStart(2,'0'), mm=String(now.getMonth()+1).padStart(2,'0'), yyyy=now.getFullYear();
  el.textContent = fmt==='mdy' ? mm+'.'+dd+'.'+yyyy : dd+'.'+mm+'.'+yyyy;
}
updateSample('${dateFmt}');
</script>
</body></html>`;
}

function renderUsersPage({ users, blocked = [], theme = 'dark', error, success }) {
  const userRows = users.map(u => {
    const isAdmin = u.is_admin === 1;
    const created = u.created_at ? u.created_at.split(' ')[0] : '—';
    return `
    <div class="folder-item" style="margin-bottom:10px">
      <div class="folder-hdr" style="cursor:default;align-items:center">
        <span style="font-size:1rem">${isAdmin ? '🛡️' : '👤'}</span>
        <span style="font-weight:600;flex:1">${u.username}</span>
        ${isAdmin ? '<span class="badge" style="background:rgba(91,156,246,.12);color:var(--accent);border:1px solid rgba(91,156,246,.3);padding:2px 10px;border-radius:20px;font-size:.75rem">Admin</span>' : ''}
        <span style="color:var(--muted);font-size:.8rem;margin-left:8px">Created ${created}</span>
        ${!isAdmin ? `<button class="btn btn-ghost btn-sm" style="margin-left:10px" onclick="showPwModal(${u.id},'${u.username}')">Change Password</button>` : ''}
        ${!isAdmin ? `<button class="btn btn-red btn-sm" style="margin-left:6px" onclick="showDelModal(${u.id},'${u.username}')">Delete</button>` : ''}
      </div>
    </div>`;
  }).join('');

  return `<!DOCTYPE html><html lang="en" data-theme="${theme}"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>User Management – Simple Sync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}
  .section{margin-bottom:28px}
  .section h3{font-size:.95rem;font-weight:600;color:var(--text);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border)}
  .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;align-items:center;justify-content:center}
  .modal-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:28px 24px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.4)}
  .modal-title{font-size:1.1rem;font-weight:600;margin-bottom:16px}
</style></head><body>
<div class="hdr">
  <div class="logo">${LOGO_SVG} Simple Sync Server</div>
  <span class="badge hdr-hide">Admin</span>
  <div class="ml">
    <span class="hdr-hide" style="color:var(--muted);font-size:.85rem">🛡️ admin</span>
    <a href="/settings" class="btn btn-ghost btn-sm">Settings</a>
    <div class="theme-pill">
      <button onclick="setTheme('dark')" class="${theme==='dark'?'active':''}" id="hbtn-dark">🌙</button>
      <button onclick="setTheme('light')" class="${theme==='light'?'active':''}" id="hbtn-light">☀️</button>
    </div>
    <form method="POST" action="/logout" style="display:inline">
      <button class="btn btn-ghost btn-sm" type="submit">Sign Out</button>
    </form>
  </div>
</div>
<div class="wrap" style="max-width:860px">
  <h2 style="margin-bottom:4px;color:var(--text)">👥 User Management</h2>
  <p style="color:var(--muted);font-size:.85rem;margin-bottom:22px">Create and manage user accounts. Each user gets their own API key for syncing.</p>

  ${error ? `<div class="err">${error}</div>` : ''}
  ${success ? `<div class="ok">✓ ${success}</div>` : ''}

  <div class="grid2" style="margin-bottom:28px">
    <div class="card section">
      <h3>➕ Create New User</h3>
      <form method="POST" action="/users/create">
        <div class="form-group"><label>Username</label>
          <input type="text" name="username" placeholder="e.g. alice" maxlength="63" required autocomplete="off"></div>
        <div class="form-group"><label>Password (min 8 characters)</label>
          <input type="password" name="password" required autocomplete="new-password"></div>
        <div class="form-group"><label>Confirm Password</label>
          <input type="password" name="confirm_password" required autocomplete="new-password"></div>
        <button class="btn btn-primary btn-sm" type="submit">Create User</button>
      </form>
    </div>
    <div class="card section">
      <h3>ℹ️ About Users</h3>
      <p style="color:var(--muted);font-size:.85rem;line-height:1.6">
        Each user gets their own isolated API key, sync folders, and file storage.<br><br>
        Usernames <strong style="color:var(--text)">cannot be changed</strong> after creation.<br><br>
        The <strong style="color:var(--text)">admin</strong> account is for user management only and cannot upload or sync files.<br><br>
        Users log in at <code style="color:var(--accent2)">/login</code> and use their API key in the companion app.
      </p>
    </div>
  </div>

  <div class="section-title">👤 All Users (${users.length})</div>
  ${userRows}

  <div class="section-title">🚫 Blocked IPs (${blocked.length})</div>
  ${blocked.length === 0
    ? '<p style="color:var(--muted);font-size:.85rem;padding:10px 0 20px">No IPs are currently blocked.</p>'
    : blocked.map(b => `
    <div class="folder-item" style="margin-bottom:10px">
      <div class="folder-hdr" style="cursor:default">
        <span style="font-size:1rem">🚫</span>
        <span style="font-weight:600;font-family:monospace;flex:1">${b.ip}</span>
        <span style="color:var(--muted);font-size:.8rem;margin-right:12px">Blocked ${b.blocked_at.split(' ')[0]}</span>
        <form method="POST" action="/users/unblock" style="display:inline">
          <input type="hidden" name="ip" value="${b.ip}">
          <button class="btn btn-ghost btn-sm" type="submit" onclick="return confirm('Unblock ${b.ip}?')">Unblock</button>
        </form>
      </div>
    </div>`).join('')
  }
</div>
<div id="toast"></div>

<!-- Delete user modal -->
<div id="delModal" class="modal-overlay">
  <div class="modal-box">
    <div class="modal-title">Delete User?</div>
    <p style="color:var(--muted);font-size:.9rem;margin-bottom:20px">This will permanently delete user <strong id="delName" style="color:var(--text)"></strong> and all their data. <strong style="color:var(--red)">This cannot be undone.</strong></p>
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" onclick="hideDelModal()">Cancel</button>
      <form id="delForm" method="POST" action="/users/delete" style="display:inline">
        <input type="hidden" id="delUserId" name="user_id" value="">
        <button class="btn btn-red btn-sm" type="submit">Yes, Delete</button>
      </form>
    </div>
  </div>
</div>

<!-- Change password modal -->
<div id="pwModal" class="modal-overlay">
  <div class="modal-box">
    <div class="modal-title">Change Password for <span id="pwName" style="color:var(--accent)"></span></div>
    <form method="POST" action="/users/change-password">
      <input type="hidden" id="pwUserId" name="user_id" value="">
      <div class="form-group"><label>New Password (min 8 characters)</label>
        <input type="password" name="new_password" id="pwInput" required autocomplete="new-password"></div>
      <div class="form-group"><label>Confirm Password</label>
        <input type="password" name="confirm_password" required autocomplete="new-password"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:8px">
        <button type="button" class="btn btn-ghost btn-sm" onclick="hidePwModal()">Cancel</button>
        <button type="submit" class="btn btn-primary btn-sm">Update Password</button>
      </div>
    </form>
  </div>
</div>

<script>
function toast(m){const el=document.getElementById('toast');el.textContent=m;el.className='show';clearTimeout(el._t);el._t=setTimeout(()=>el.className='',3000)}
function setTheme(t){
  document.documentElement.setAttribute('data-theme',t);
  ['dark','light'].forEach(x=>{
    const b=document.getElementById('hbtn-'+x);
    if(b) b.className = x===t?'active':'';
  });
  fetch('/settings/theme',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'theme='+t});
}
function showDelModal(id, name){
  document.getElementById('delUserId').value = id;
  document.getElementById('delName').textContent = name;
  const m = document.getElementById('delModal');
  m.style.display='flex'; m.onclick=e=>{if(e.target===m)hideDelModal()};
}
function hideDelModal(){document.getElementById('delModal').style.display='none';}
function showPwModal(id, name){
  document.getElementById('pwUserId').value = id;
  document.getElementById('pwName').textContent = name;
  document.getElementById('pwInput').value = '';
  const m = document.getElementById('pwModal');
  m.style.display='flex'; m.onclick=e=>{if(e.target===m)hidePwModal()};
  setTimeout(()=>document.getElementById('pwInput').focus(),50);
}
function hidePwModal(){document.getElementById('pwModal').style.display='none';}
</script>
</body></html>`;
}