'use strict';

const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const Database = require('better-sqlite3');

const VERSION = '1.3.1';


const CONFIG_DIR = process.env.CONFIG_DIR || '/config';
const DATA_DIR   = process.env.DATA_DIR   || '/data';
const DB_PATH    = path.join(CONFIG_DIR, 'sss.db');
const TMP_DIR    = path.join(DATA_DIR, '.tmp');

[CONFIG_DIR, DATA_DIR, TMP_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

try {
    fs.readdirSync(TMP_DIR).forEach(f => {
        try { fs.unlinkSync(path.join(TMP_DIR, f)); } catch {}
    });
} catch {}

(function migrateIfNeeded() {
    const probe = new Database(DB_PATH);
    try { probe.pragma('wal_checkpoint(FULL)'); } catch {}
    
    const tables = probe.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r => r.name);
    
    if (!tables.includes('uploaded_files')) {
        probe.close();
        return;
    }
    
    const cols = probe.pragma('table_info(uploaded_files)').map(c => c.name);
    if (!cols.includes('android_path')) {
        probe.close();
        return;
    }
    
    console.log('[MIGRATION] Old schema detected — building new database...');
    
    const tmpPath = DB_PATH.replace(/\.db$/, '-temp.db');
    const bakPath = DB_PATH.replace(/\.db$/, '.db.bak');
    
    [tmpPath, tmpPath + '-shm', tmpPath + '-wal'].forEach(f => {
        try { fs.unlinkSync(f); } catch {}
    });
    
    try {
        const tmp = new Database(tmpPath);
        tmp.pragma('journal_mode = WAL');
        tmp.pragma('synchronous = NORMAL');
        tmp.pragma('foreign_keys = ON');
        
        tmp.exec(`
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                api_key TEXT UNIQUE NOT NULL,
                label TEXT NOT NULL DEFAULT 'Default',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(user_id, name),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE uploaded_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER NOT NULL,
                hash TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                relative_path TEXT NOT NULL,
                date_folder TEXT NOT NULL,
                uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
            );
            CREATE INDEX idx_hash ON uploaded_files(hash);
            CREATE INDEX idx_user_folder ON uploaded_files(user_id, folder_id);
            CREATE UNIQUE INDEX idx_user_folder_hash ON uploaded_files(user_id, folder_id, hash);
            CREATE INDEX idx_hash_lookup ON uploaded_files(user_id, folder_id, hash, id);
            CREATE TABLE blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_at TEXT NOT NULL DEFAULT (datetime('now')),
                reason TEXT NOT NULL DEFAULT 'Too many failed login attempts'
            );
        `);
        
        const copyAll = tmp.transaction(() => {
            for (const row of probe.prepare('SELECT * FROM settings').all()) {
                tmp.prepare('INSERT OR IGNORE INTO settings VALUES (?,?)').run(row.key, row.value);
            }
            
            for (const row of probe.prepare('SELECT * FROM users').all()) {
                tmp.prepare('INSERT INTO users (id,username,password_hash,is_admin,must_change_password,created_at) VALUES (?,?,?,?,?,?)')
                    .run(row.id, row.username, row.password_hash, row.is_admin ?? 0, row.must_change_password ?? 0, row.created_at);
            }
            
            for (const row of probe.prepare('SELECT * FROM api_keys').all()) {
                tmp.prepare('INSERT INTO api_keys (id,user_id,api_key,label,created_at) VALUES (?,?,?,?,?)')
                    .run(row.id, row.user_id, row.api_key, row.label ?? 'Default', row.created_at);
            }
            
            for (const row of probe.prepare('SELECT * FROM folders').all()) {
                tmp.prepare('INSERT INTO folders (id,user_id,name,created_at) VALUES (?,?,?,?)')
                    .run(row.id, row.user_id, row.name, row.created_at);
            }
            
            const rows = probe.prepare(`
                SELECT id, user_id, folder_id, hash, filename, file_size,
                       COALESCE(android_path, server_path, filename) AS relative_path,
                       date_folder, uploaded_at
                FROM uploaded_files
                WHERE id IN (SELECT MAX(id) FROM uploaded_files GROUP BY user_id, folder_id, hash)
            `).all();
            
            for (const row of rows) {
                tmp.prepare('INSERT INTO uploaded_files (id,user_id,folder_id,hash,filename,file_size,relative_path,date_folder,uploaded_at) VALUES (?,?,?,?,?,?,?,?,?)')
                    .run(row.id, row.user_id, row.folder_id, row.hash, row.filename, row.file_size, row.relative_path, row.date_folder, row.uploaded_at);
            }
            
            for (const row of probe.prepare('SELECT * FROM blocked_ips').all()) {
                tmp.prepare('INSERT OR IGNORE INTO blocked_ips (ip,blocked_at,reason) VALUES (?,?,?)').run(row.ip, row.blocked_at, row.reason);
            }
        });
        
        copyAll();
        
        const oldCount = probe.prepare('SELECT COUNT(*) as n FROM uploaded_files').get().n;
        const newCount = tmp.prepare('SELECT COUNT(*) as n FROM uploaded_files').get().n;
        const dupes = oldCount - newCount;
        
        if (newCount === 0 && oldCount > 0) {
            throw new Error('New DB has no uploaded_files rows');
        }
        
        tmp.pragma('wal_checkpoint(TRUNCATE)');
        tmp.close();
        probe.close();
        
        [bakPath, bakPath + '-shm', bakPath + '-wal'].forEach(f => {
            try { fs.unlinkSync(f); } catch {}
        });
        
        fs.renameSync(DB_PATH, bakPath);
        try { fs.renameSync(DB_PATH + '-shm', bakPath + '-shm'); } catch {}
        try { fs.renameSync(DB_PATH + '-wal', bakPath + '-wal'); } catch {}
        
        fs.renameSync(tmpPath, DB_PATH);
        try { fs.renameSync(tmpPath + '-shm', DB_PATH + '-shm'); } catch {}
        try { fs.renameSync(tmpPath + '-wal', DB_PATH + '-wal'); } catch {}
        
        const dupMsg = dupes > 0 ? `, ${dupes} duplicate${dupes === 1 ? '' : 's'} removed` : '';
        console.log(`[MIGRATION] Complete — ${newCount} rows migrated${dupMsg}. Old DB kept at: ${bakPath}`);
    } catch (err) {
        console.error('[MIGRATION] FAILED:', err.message);
        console.error('[MIGRATION] sss.db untouched. Remove sss-temp.db manually if present.');
        process.exit(1);
    }
})();

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');
db.pragma('cache_size = -20000');

let lastUploadAt = Date.now();
const activeUploads = new Set();

db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        integrity_check INTEGER NOT NULL DEFAULT 0,
        locked_until INTEGER NOT NULL DEFAULT 0
    );
    
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        label TEXT NOT NULL DEFAULT 'Default',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(user_id, name),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS uploaded_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        folder_id INTEGER NOT NULL,
        hash TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        relative_path TEXT NOT NULL,
        date_folder TEXT NOT NULL,
        uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_hash ON uploaded_files(hash);
    CREATE INDEX IF NOT EXISTS idx_user_folder ON uploaded_files(user_id, folder_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_user_folder_hash ON uploaded_files(user_id, folder_id, hash);
    CREATE INDEX IF NOT EXISTS idx_hash_lookup ON uploaded_files(user_id, folder_id, hash, id);
    
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        blocked_at TEXT NOT NULL DEFAULT (datetime('now')),
        reason TEXT NOT NULL DEFAULT 'Too many failed login attempts',
        country TEXT,
        city TEXT
    );

    CREATE TABLE IF NOT EXISTS security_events (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        ip    TEXT NOT NULL,
        event TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        country TEXT,
        city TEXT
    );

    CREATE TABLE IF NOT EXISTS whatsapp_files (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL,
        relative_path TEXT NOT NULL,
        hash          TEXT NOT NULL,
        file_size     INTEGER NOT NULL,
        backed_up_at  TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(user_id, relative_path),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
`);

try {
    db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
} catch {}

try {
    db.exec('ALTER TABLE users ADD COLUMN integrity_check INTEGER NOT NULL DEFAULT 0');
} catch {}

try {
    db.exec('ALTER TABLE users ADD COLUMN locked_until INTEGER NOT NULL DEFAULT 0');
} catch {}

try {
    db.exec('ALTER TABLE blocked_ips ADD COLUMN country TEXT');
} catch {}

try {
    db.exec('ALTER TABLE blocked_ips ADD COLUMN city TEXT');
} catch {}

try {
    db.exec('ALTER TABLE security_events ADD COLUMN country TEXT');
} catch {}

try {
    db.exec('ALTER TABLE security_events ADD COLUMN city TEXT');
} catch {}

db.prepare('UPDATE users SET is_admin = 1 WHERE username = ?').run('admin');

function getSetting(key) {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    return row ? row.value : null;
}

function setSetting(key, value) {
    db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)').run(key, value);
}

if (!getSetting('api_keys_hashed')) {
    const plainKeys = db.prepare('SELECT id, api_key FROM api_keys').all();
    const hashKeys = db.transaction(() => {
        for (const row of plainKeys) {
            const hashed = crypto.createHash('sha256').update(row.api_key).digest('hex');
            db.prepare('UPDATE api_keys SET api_key = ? WHERE id = ?').run(hashed, row.id);
        }
    });
    hashKeys();
    setSetting('api_keys_hashed', '1');
    if (plainKeys.length > 0) {
        console.log(`[SECURITY] ${plainKeys.length} API key${plainKeys.length !== 1 ? 's' : ''} migrated to hashed storage. Existing keys continue to work normally.`);
    }
}

function generateApiKey() {
    const raw = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    return { raw, hash };
}

function hashApiKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

function generateSessionSecret() {
    return crypto.randomBytes(48).toString('hex');
}

function generatePassword() {
    const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#';
    return Array.from({ length: 14 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function todayStr(fmt) {
    const d = new Date();
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yyyy = d.getFullYear();
    return fmt === 'mdy' ? `${mm}.${dd}.${yyyy}` : `${dd}.${mm}.${yyyy}`;
}

function getUserDateFmt(userId) {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(`datefmt_user_${userId}`);
    return row ? row.value : 'dmy';
}

function setUserDateFmt(userId, fmt) {
    db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(`datefmt_user_${userId}`, fmt);
}

function safeName(n) {
    return typeof n === 'string' && /^[a-zA-Z0-9_\-. ]{1,63}$/.test(n) && !n.startsWith('.');
}

function isStrongPassword(p) {
    return p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/.test(p);
}

function fmtBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
}

function getDiskStats(dir) {
    try {
        const stats = fs.statfsSync(dir);
        const total = stats.blocks * stats.bsize;
        const free = stats.bfree * stats.bsize;
        const used = total - free;
        return { total, used, free };
    } catch {
        return null;
    }
}

function allFolderStats(userId) {
    const rows = db.prepare(`
        SELECT folder_id, date_folder AS date, COUNT(*) AS count, SUM(file_size) AS totalBytes
        FROM uploaded_files
        WHERE user_id = ?
        GROUP BY folder_id, date_folder
        ORDER BY folder_id, date_folder DESC
    `).all(userId);
    const map = new Map();
    for (const r of rows) {
        if (!map.has(r.folder_id)) map.set(r.folder_id, []);
        map.get(r.folder_id).push({ date: r.date, count: r.count, totalBytes: r.totalBytes });
    }
    return map;
}

function runIntegrityCheck(userId) {
    const rows = db.prepare(`
        SELECT uf.id, uf.relative_path, uf.date_folder, uf.hash,
               f.name AS folder_name, u.username
        FROM uploaded_files uf
        JOIN folders f ON f.id = uf.folder_id
        JOIN users u ON u.id = uf.user_id
        WHERE uf.user_id = ?
    `).all(userId);
    
    const missing = [];
    
    for (const row of rows) {
        const fullPath = path.join(DATA_DIR, row.username, row.folder_name, row.date_folder, row.relative_path);
        
        if (!fs.existsSync(fullPath)) {
            missing.push(row.id);
        }
    }
    
    if (missing.length > 0) {
        const placeholders = missing.map(() => '?').join(',');
        db.prepare(`DELETE FROM uploaded_files WHERE id IN (${placeholders})`).run(...missing);
        db.prepare('UPDATE users SET integrity_check = 1 WHERE id = ?').run(userId);
    }
    
    return { checked: rows.length, removed: missing.length };
}

function getUserTheme(userId) {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(`theme_user_${userId}`);
    return row ? row.value : 'dark';
}

function setUserTheme(userId, theme) {
    db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)').run(`theme_user_${userId}`, theme);
}

function getWhatsAppStats(userId) {
    const row = db.prepare(`
        SELECT COUNT(*) as totalFiles, COALESCE(SUM(file_size), 0) as totalBytes,
               MAX(backed_up_at) as lastBackup
        FROM whatsapp_files WHERE user_id = ?
    `).get(userId);
    return row || { totalFiles: 0, totalBytes: 0, lastBackup: null };
}

module.exports = {
    db, TMP_DIR, DATA_DIR, CONFIG_DIR, VERSION,
    getSetting, setSetting, generateApiKey, hashApiKey, generateSessionSecret,
    generatePassword, todayStr, getUserDateFmt, setUserDateFmt, safeName,
    isStrongPassword, fmtBytes, getDiskStats, allFolderStats, runIntegrityCheck,
    getUserTheme, setUserTheme, getWhatsAppStats,
    get lastUploadAt() { return lastUploadAt; },
    set lastUploadAt(v) { lastUploadAt = v; },
    activeUploads,
};
