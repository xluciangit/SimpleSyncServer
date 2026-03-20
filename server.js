'use strict';

const express      = require('express');
const path         = require('path');
const crypto       = require('crypto');
const session      = require('express-session');
const cookieParser = require('cookie-parser');
const csrfLib      = require('./lib/csrf');
const helmet       = require('helmet');
const multer       = require('multer');
const bcrypt       = require('bcryptjs');

const dbLib    = require('./lib/db');
const security = require('./lib/security');
const { renderDashboard } = require('./views/templates');

const { db, TMP_DIR, generateSessionSecret, generatePassword,
        allFolderStats, fmtBytes, getDiskStats, VERSION } = dbLib;
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

const SESSION_SECRET = process.env.SESSION_SECRET || generateSessionSecret();

const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.set('etag', false);

app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
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
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(__dirname, 'static', 'favicon.ico')));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use(cookieParser());
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    rolling: true,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: 'auto',
        sameSite: 'strict'
    }
}));

const csrfProtection = csrfLib.csrfProtection;

function dynamicUpload(req, res, next) {
    const val = parseInt(dbLib.getSetting('upload_max_bytes'), 10);
    const opts = { dest: TMP_DIR };
    if (Number.isFinite(val) && val > 0) opts.limits = { fileSize: val };
    multer(opts).single('file')(req, res, next);
}

require('./routes/auth')(app);
require('./routes/settings')(app);
require('./routes/users')(app);
require('./routes/api')(app, dynamicUpload);

app.get('/', requireSession, csrfProtection, async (req, res) => {
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

    await renderDashboard(res, {
        username: user.username,
        apiKey: apiKeyRow ? apiKeyRow.api_key : null,
        folders: foldersWithStats,
        totalFiles,
        totalBytes: fmtBytes(totalBytes),
        uptime: upParts.join(' '),
        theme,
        csrfToken: csrfLib.generateToken(req),
        diskFree: disk ? fmtBytes(disk.free) : 'N/A',
        diskUsed: disk ? fmtBytes(disk.used) : 'N/A',
        diskTotal: disk ? fmtBytes(disk.total) : 'N/A',
        folderError: req.query.err ? decodeURIComponent(req.query.err) : null,
        flashMsg: req.query.msg ? decodeURIComponent(req.query.msg) : null,
        nonce: res.locals.cspNonce
    });
});

app.use((err, req, res, next) => {
    if (err?.status === 403) {
        return res.status(403).send('Form session expired or invalid. Please go back and try again.');
    }
    next(err);
});

app.listen(PORT, '0.0.0.0', () => {
    const label  = `SimpleSync Server v${VERSION}`;
    const border = '='.repeat(46);
    const padded = label.padEnd(42);
    console.log(`╔${border}╗`);
    console.log(`║  ${padded}  ║`);
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

setInterval(() => {
    if (new Date().getDate() === 1) {
        try {
            db.prepare("DELETE FROM security_events WHERE created_at < datetime('now', '-30 days')").run();
        } catch {}
    }
}, 24 * 60 * 60 * 1000);

async function enrichSecurityEvents() {
    const rows = db.prepare(
        'SELECT id, ip FROM security_events WHERE country IS NULL AND ip != ? ORDER BY created_at DESC LIMIT 45'
    ).all('unknown');

    if (rows.length === 0) return;

    for (const row of rows) {
        try {
            const res = await fetch(`http://ip-api.com/json/${row.ip}?fields=country,city,query`, {
                signal: AbortSignal.timeout(3000)
            });
            if (!res.ok) continue;
            const data = await res.json();
            const country = data.country || null;
            const city    = data.city    || null;
            db.prepare('UPDATE security_events SET country = ?, city = ? WHERE id = ?').run(country, city, row.id);
        } catch {}
        await new Promise(r => setTimeout(r, 1400));
    }

    const remaining = db.prepare(
        'SELECT COUNT(*) as n FROM security_events WHERE country IS NULL AND ip != ?'
    ).get('unknown').n;

    if (remaining > 0) {
        console.log(`[GEO] ${remaining} security event(s) still need geo lookup — will retry on next startup.`);
        dbLib.setSetting('geo_enrich_pending', '1');
    } else {
        dbLib.setSetting('geo_enrich_pending', '0');
    }
}

const geoPending = dbLib.getSetting('geo_enrich_pending');
const hasUnenriched = db.prepare(
    'SELECT COUNT(*) as n FROM security_events WHERE country IS NULL AND ip != ?'
).get('unknown').n > 0;

if (geoPending === '1' || hasUnenriched) {
    setTimeout(() => enrichSecurityEvents(), 5000);
}

function shutdown() {
    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch {}
    db.close();
    process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
