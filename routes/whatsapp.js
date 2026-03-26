'use strict';

const fs      = require('fs');
const path    = require('path');
const multer  = require('multer');
const dbLib   = require('../lib/db');
const { db, DATA_DIR, TMP_DIR, fmtBytes, getWhatsAppStats } = dbLib;
const { waLimiter, apiAuth } = require('../lib/security');
const logger = require('../lib/logger');

const WA_FOLDER = 'WhatsApp';

function waRoot(username) {
    return path.join(DATA_DIR, username, WA_FOLDER);
}

function safePath(username, relPath) {
    const root = waRoot(username);
    const resolved = path.resolve(root, relPath);
    if (!resolved.startsWith(root + path.sep) && resolved !== root) return null;
    return resolved;
}

function dynamicUpload(req, res, next) {
    multer({ dest: TMP_DIR }).single('file')(req, res, next);
}

module.exports = function(app) {

app.get('/api/whatsapp/status', apiAuth, (req, res) => {
    const stats = getWhatsAppStats(req.apiUserId);
    res.json({
        totalFiles: stats.totalFiles,
        totalBytes: stats.totalBytes,
        lastBackup: stats.lastBackup || null,
        hasBackup:  stats.totalFiles > 0
    });
});

app.post('/api/whatsapp/check', waLimiter, apiAuth, (req, res) => {
    const { relative_path, hash } = req.body;

    if (!relative_path || !hash) {
        return res.status(400).json({ error: 'Missing relative_path or hash' });
    }

    const row = db.prepare(
        'SELECT hash FROM whatsapp_files WHERE user_id = ? AND relative_path = ?'
    ).get(req.apiUserId, relative_path);

    if (!row) {
        return res.json({ exists: false, changed: false });
    }

    res.json({ exists: true, changed: row.hash !== hash });
});

app.post('/api/whatsapp/upload', waLimiter, apiAuth, dynamicUpload, (req, res) => {
    if (dbLib.activeUploads.has(req.apiUserId)) {
        return res.status(503).json({ error: 'Upload already in progress for this account' });
    }

    dbLib.activeUploads.add(req.apiUserId);
    let released = false;
    const release = () => {
        if (released) return;
        released = true;
        dbLib.activeUploads.delete(req.apiUserId);
    };
    res.on('finish', release);
    res.on('close',  release);
    req.on('close',  release);
    req.on('error',  release);
    setTimeout(release, 31 * 60 * 1000).unref();

    const { relative_path, hash } = req.body;
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: 'No file' });
    }

    if (!relative_path || !hash) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Missing relative_path or hash' });
    }

    if (/\.\.[\\/]|\.\.$/.test(relative_path)) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Invalid file path' });
    }

    const safeRel = path.normalize(relative_path).replace(/[<>:"|?*\x00-\x1F]/g, '');
    if (safeRel.includes('..')) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Invalid file path' });
    }

    const destFile = safePath(req.apiUsername, safeRel);
    if (!destFile) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Invalid file path' });
    }

    const destDir = path.dirname(destFile);

    try {
        fs.mkdirSync(destDir, { recursive: true });
        try {
            fs.renameSync(file.path, destFile);
        } catch (e) {
            if (e.code === 'EXDEV') {
                fs.copyFileSync(file.path, destFile);
                try { fs.unlinkSync(file.path); } catch {}
            } else {
                throw e;
            }
        }
    } catch (e) {
        try { fs.unlinkSync(file.path); } catch {}
        if (e.code === 'ENOSPC') {
            logger.logUploadFailed(req.apiUsername, 'WhatsApp', path.basename(safeRel), 'storage full');
            return res.status(507).json({ error: 'Server storage is full' });
        }
        logger.logUploadFailed(req.apiUsername, 'WhatsApp', path.basename(safeRel), 'server error');
        return res.status(500).json({ error: 'Upload failed' });
    }

    try {
        db.prepare(`
            INSERT INTO whatsapp_files (user_id, relative_path, hash, file_size, backed_up_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(user_id, relative_path) DO UPDATE SET
                hash        = excluded.hash,
                file_size   = excluded.file_size,
                backed_up_at = excluded.backed_up_at
        `).run(req.apiUserId, safeRel, hash, file.size);
    } catch (e) {
        try { fs.unlinkSync(destFile); } catch {}
        logger.logUploadFailed(req.apiUsername, 'WhatsApp', path.basename(safeRel), 'db error');
        return res.status(500).json({ error: 'Upload failed' });
    }

    dbLib.lastUploadAt = Date.now();
    logger.trackUpload(req.apiUsername, req.apiUserId, 'WhatsApp', file.size, true);
    res.json({ ok: true });
});

app.get('/api/whatsapp/files', apiAuth, (req, res) => {
    const rows = db.prepare(
        'SELECT relative_path, hash, file_size, backed_up_at FROM whatsapp_files WHERE user_id = ? ORDER BY relative_path ASC'
    ).all(req.apiUserId);
    res.json(rows);
});

app.get('/api/whatsapp/download', apiAuth, (req, res) => {
    const relPath = req.query.path;

    if (!relPath) {
        return res.status(400).json({ error: 'Missing path' });
    }

    const filePath = safePath(req.apiUsername, relPath);
    if (!filePath) {
        return res.status(400).json({ error: 'Invalid path' });
    }

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }

    res.download(filePath, path.basename(filePath));
});

};