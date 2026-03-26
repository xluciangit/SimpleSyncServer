'use strict';

const fs   = require('fs');
const path = require('path');
const dbLib = require('../lib/db');
const { db, getSetting, getUserDateFmt, safeName, allFolderStats, fmtBytes,
        todayStr, DATA_DIR, VERSION } = dbLib;
const { apiLimiter, apiAuth } = require('../lib/security');
const logger = require('../lib/logger');

module.exports = function(app, upload) {

app.get('/api/ping', (req, res) => {
    res.json({ ok: true, version: VERSION, app: 'SimpleSync Server' });
});

app.get('/health', (req, res) => {
    try {
        db.prepare('SELECT 1').get();
        res.json({ status: 'ok', uptime: Math.floor(process.uptime()) });
    } catch {
        res.status(503).json({ status: 'error' });
    }
});

app.get('/api/config', apiAuth, (req, res) => {
    const maxBytes = parseInt(getSetting('upload_max_bytes'), 10);
    res.json({
        local_url:        getSetting('local_url') || null,
        upload_max_bytes: Number.isFinite(maxBytes) ? maxBytes : null
    });
});

app.post('/api/check-hash', apiLimiter, apiAuth, (req, res) => {
    const { hash, folder } = req.body;
    
    if (!hash || !folder) {
        return res.status(400).json({ error: 'Missing hash or folder' });
    }
    
    const folderRow = db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ?')
        .get(req.apiUserId, folder);
    
    if (!folderRow) {
        return res.json({ exists: false });
    }
    
    const row = db.prepare(`
        SELECT id FROM uploaded_files 
        WHERE user_id = ? AND folder_id = ? AND hash = ? 
        LIMIT 1
    `).get(req.apiUserId, folderRow.id, hash);
    
    res.json({ exists: !!row });
});

app.post('/api/upload', apiLimiter, apiAuth, upload, (req, res) => {
    if (dbLib.activeUploads.has(req.apiUserId)) {
        return res.status(503).json({ error: 'Upload already in progress for this account' });
    }

    dbLib.activeUploads.add(req.apiUserId);

    let released = false;
    const releaseUpload = () => {
        if (released) return;
        released = true;
        dbLib.activeUploads.delete(req.apiUserId);
    };
    res.on('finish', releaseUpload);
    res.on('close',  releaseUpload);
    req.on('close',  releaseUpload);
    req.on('error',  releaseUpload);
    setTimeout(releaseUpload, 31 * 60 * 1000).unref();
    
    const folder = req.body?.folder;
    const relative_path = req.body?.relative_path;
    const hash = req.body?.hash;
    const file = req.file;
    
    if (!file) {
        return res.status(400).json({ error: 'No file' });
    }
    
    if (!folder || !relative_path) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Missing folder or relative_path' });
    }
    
    if (!safeName(folder)) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Invalid folder name' });
    }
    
    const username = req.apiUsername;
    const fmt = getUserDateFmt(req.apiUserId);
    const date = todayStr(fmt);
    
    if (/\.\.[\\/]|\.\.$/.test(relative_path)) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Invalid file path' });
    }
    const safeRelative = path.normalize(relative_path).replace(/[<>:"|?*\x00-\x1F]/g, '');
    if (safeRelative.includes('..')) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Invalid file path' });
    }
    const userRoot = path.resolve(DATA_DIR, username);
    const destFile = path.resolve(userRoot, folder, date, safeRelative);
    const destDir = path.dirname(destFile);
    
    if (!destFile.startsWith(userRoot + path.sep)) {
        try { fs.unlinkSync(file.path); } catch {}
        return res.status(400).json({ error: 'Invalid file path' });
    }
    
    let folderRow = db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ?')
        .get(req.apiUserId, folder);
    
    if (!folderRow) {
        const r = db.prepare('INSERT INTO folders (user_id, name) VALUES (?, ?)').run(req.apiUserId, folder);
        folderRow = { id: r.lastInsertRowid };
    }
    
    if (hash) {
        const dup = db.prepare(`
            SELECT id FROM uploaded_files 
            WHERE user_id = ? AND folder_id = ? AND hash = ? 
            LIMIT 1
        `).get(req.apiUserId, folderRow.id, hash);
        
        if (dup) {
            try { fs.unlinkSync(file.path); } catch {}
            return res.json({ ok: true, skipped: true });
        }
    }
    
    try {
        fs.mkdirSync(destDir, { recursive: true });
        
        try {
            fs.renameSync(file.path, destFile);
        } catch (renameErr) {
            if (renameErr.code === 'EXDEV') {
                fs.copyFileSync(file.path, destFile);
                try { fs.unlinkSync(file.path); } catch {}
            } else {
                throw renameErr;
            }
        }
    } catch (e) {
        try { fs.unlinkSync(file.path); } catch {}
        
        if (e.code === 'ENOSPC') {
            logger.logUploadFailed(username, folder, path.basename(safeRelative), 'storage full');
            return res.status(507).json({ error: 'Server storage is full' });
        }
        
        logger.logUploadFailed(username, folder, path.basename(safeRelative), 'server error');
        return res.status(500).json({ error: 'Upload failed' });
    }
    
    try {
        db.transaction(() => {
            db.prepare(`
                INSERT INTO uploaded_files (user_id, folder_id, hash, filename, file_size, relative_path, date_folder)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(
                req.apiUserId,
                folderRow.id,
                hash || '',
                path.basename(safeRelative),
                file.size,
                safeRelative,
                date
            );
        })();
    } catch (e) {
        if (e.message && e.message.includes('UNIQUE')) {
            try { fs.unlinkSync(destFile); } catch {}
            return res.json({ ok: true, skipped: true });
        }
        try { fs.unlinkSync(destFile); } catch {}
        logger.logUploadFailed(username, folder, path.basename(safeRelative), 'db error');
        return res.status(500).json({ error: 'Upload failed' });
    }
    
    dbLib.lastUploadAt = Date.now();
    logger.trackUpload(username, req.apiUserId, folder, file.size, false);
    res.json({ ok: true, stored: path.join(username, folder, date, safeRelative) });
});

app.get('/api/folders', apiAuth, (req, res) => {
    const folders = db.prepare('SELECT * FROM folders WHERE user_id = ? ORDER BY name ASC').all(req.apiUserId);
    const statsMap = allFolderStats(req.apiUserId);
    res.json(folders.map(f => ({ ...f, stats: statsMap.get(f.id) || [] })));
});

app.post('/api/folders', apiAuth, (req, res) => {
    const { name } = req.body;
    
    if (!safeName(name)) {
        return res.status(400).json({ error: 'Invalid folder name' });
    }
    
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.apiUserId);
    
    try {
        db.prepare('INSERT INTO folders (user_id, name) VALUES (?, ?)').run(req.apiUserId, name.trim());
        fs.mkdirSync(path.join(DATA_DIR, user.username, name.trim()), { recursive: true });
        res.json({ ok: true });
    } catch (e) {
        if (e.message.includes('UNIQUE')) {
            return res.status(409).json({ error: 'Folder already exists' });
        }
        res.status(500).json({ error: 'Failed to create folder' });
    }
});

app.get('/api/stats', apiAuth, (req, res) => {
    const count = db.prepare('SELECT COUNT(*) as n, SUM(file_size) as total FROM uploaded_files WHERE user_id = ?').get(req.apiUserId);
    
    res.json({
        folders: db.prepare('SELECT COUNT(*) as n FROM folders WHERE user_id = ?').get(req.apiUserId).n,
        totalFiles: count.n || 0,
        totalBytes: fmtBytes(count.total || 0),
        uptime: Math.floor(process.uptime())
    });
});

app.get('/api/integrity-status', apiAuth, (req, res) => {
    const user = db.prepare('SELECT integrity_check FROM users WHERE id = ?').get(req.apiUserId);
    res.json({ flag: user ? (user.integrity_check || 0) : 0 });
});

app.post('/api/integrity-acknowledge', apiAuth, (req, res) => {
    db.prepare('UPDATE users SET integrity_check = 0 WHERE id = ?').run(req.apiUserId);
    res.json({ ok: true });
});

app.get('/api/folders/validate', apiAuth, (req, res) => {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Missing name' });

    const folderRow = db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ?')
        .get(req.apiUserId, name);
    const inDb = !!folderRow;

    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.apiUserId);
    const folderPath = path.join(DATA_DIR, user.username, name);
    const onDisk = fs.existsSync(folderPath);

    res.json({ inDb, onDisk });
});

};