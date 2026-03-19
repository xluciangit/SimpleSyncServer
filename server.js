'use strict';

const express      = require('express');
const cors         = require('cors');
const path         = require('path');
const session      = require('express-session');
const cookieParser = require('cookie-parser');
const csrf         = require('csurf');
const helmet       = require('helmet');
const multer       = require('multer');
const bcrypt       = require('bcryptjs');

const dbLib    = require('./lib/db');
const security = require('./lib/security');
const { renderDashboard } = require('./views/templates');

const { db, TMP_DIR, generateSessionSecret, generatePassword,
        allFolderStats, fmtBytes, getDiskStats } = dbLib;
const { requireSession } = security;

const PORT      = parseInt(process.env.PORT || '3000', 10);
const HOST_PORT = process.env.HOST_PORT || PORT;

let firstRunPassword = null;
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');

if (!adminExists) {
    firstRunPassword = generatePassword();
    const hash = bcrypt.hashSync(firstRunPassword, 10);
    db.prepare('INSERT INTO users (username, password_hash, is_admin, must_change_password) VALUES (?, ?, 1, 1)')
        .run('admin', hash);
}

const SESSION_SECRET = generateSessionSecret();

const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.set('etag', false);

app.use((req, res, next) => {
    res.locals.cspNonce = require('crypto').randomBytes(16).toString('base64');
    next();
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                (req, res) => `'nonce-${res.locals.cspNonce}'`,
                "https://static.cloudflareinsights.com"
            ],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            formAction: ["'self'"],
        }
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    noSniff: true,
    hidePoweredBy: true,
    permissionsPolicy: {
        directives: {
            "clipboard-write": ["self"]
        }
    }
}));

app.use((req, res, next) => {
    const timeout = req.path === '/api/upload' ? 10 * 60 * 1000 : 30 * 1000;
    req.setTimeout(timeout);
    res.setTimeout(timeout);
    next();
});

app.use('/static', express.static(path.join(__dirname, 'static')));
app.use(cors({ origin: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use(cookieParser());
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: 'auto',
        sameSite: 'strict'
    }
}));

const csrfProtection = csrf({ cookie: false });

function dynamicUpload(req, res, next) {
    const limitBytes = parseInt(dbLib.getSetting('upload_max_bytes'), 10) || null;
    const opts = { dest: TMP_DIR };
    if (limitBytes) opts.limits = { fileSize: limitBytes };
    multer(opts).single('file')(req, res, next);
}

require('./routes/auth')(app);
require('./routes/settings')(app);
require('./routes/users')(app);
require('./routes/api')(app, dynamicUpload);

app.get('/', requireSession, csrfProtection, (req, res) => {
    if (req.session.isAdmin) return res.redirect('/users');

    const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId);
    const apiKeyRow = db.prepare('SELECT api_key, label FROM api_keys WHERE user_id = ? LIMIT 1').get(user.id);
    const folders = db.prepare('SELECT * FROM folders WHERE user_id = ? ORDER BY name ASC').all(user.id);
    const statsMap = allFolderStats(user.id);
    const foldersWithStats = folders.map(f => ({ ...f, stats: statsMap.get(f.id) || [] }));

    let totalFiles = 0;
    let totalBytes = 0;

    foldersWithStats.forEach(f => {
        f.stats.forEach(s => {
            totalFiles += s.count;
            totalBytes += s.totalBytes;
        });
    });

    const up = Math.floor(process.uptime());
    const mins = Math.floor((up % 3600) / 60);
    const hrs = Math.floor(up / 3600) % 24;
    const days = Math.floor(up / 86400) % 30;
    const months = Math.floor(up / 2592000) % 12;
    const years  = Math.floor(up / 31536000);
    const upParts = [];
    if (years  > 0) upParts.push(years  + 'y');
    if (months > 0) upParts.push(months + 'mo');
    if (days   > 0) upParts.push(days   + 'd');
    upParts.push(hrs + 'h ' + String(mins).padStart(2, '0') + 'm');

    const disk  = getDiskStats(dbLib.DATA_DIR);
    const theme = req.session.theme || 'dark';

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderDashboard({
        username: user.username,
        apiKey: apiKeyRow ? apiKeyRow.api_key : null,
        folders: foldersWithStats,
        totalFiles,
        totalBytes: fmtBytes(totalBytes),
        uptime: upParts.join(' '),
        theme,
        csrfToken: req.csrfToken(),
        diskFree: disk ? fmtBytes(disk.free) : 'N/A',
        diskUsed: disk ? fmtBytes(disk.used) : 'N/A',
        diskTotal: disk ? fmtBytes(disk.total) : 'N/A',
        folderError: req.query.err ? decodeURIComponent(req.query.err) : null,
        flashMsg: req.query.msg ? decodeURIComponent(req.query.msg) : null,
        nonce: res.locals.cspNonce
    }));
});

app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).send('Form session expired or invalid. Please go back and try again.');
    }
    next(err);
});

app.listen(PORT, '0.0.0.0', () => {
    const border = '='.repeat(46);
    console.log(`╔${border}╗`);
    console.log(`║          SimpleSync Server v1.2.3             ║`);
    console.log(`╚${border}╝`);
    console.log(`  Port:    ${PORT} (host: ${HOST_PORT})`);
    console.log(`  Data:    ${dbLib.DATA_DIR}`);
    console.log(`  Config:  ${dbLib.CONFIG_DIR}`);

    if (firstRunPassword) {
        const b = '-'.repeat(44);
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

    console.log(`  Web UI:   http://localhost:${HOST_PORT}\n`);
});

setInterval(() => {
    if (Date.now() - dbLib.lastUploadAt >= 30 * 60 * 1000) {
        try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch {}
    }
}, 5 * 60 * 1000);

function shutdown() {
    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch {}
    db.close();
    process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
