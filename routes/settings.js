'use strict';

const fs   = require('fs');
const path = require('path');
const dbLib = require('../lib/db');
const { db, getSetting, setSetting, generateApiKey, setUserDateFmt,
        setUserTheme, isStrongPassword, DATA_DIR } = dbLib;
const { requireSession, requireAdmin, logSecurityEvent, getClientIp } = require('../lib/security');
const { renderSettings } = require('../views/templates');
const csrf   = require('csurf');
const bcrypt = require('bcryptjs');

const csrfProtection = csrf({ cookie: false });

function respondSettings(req, res, error, success) {
    const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId);
    const apiKeyRow = db.prepare('SELECT api_key, label FROM api_keys WHERE user_id = ? LIMIT 1').get(user.id);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderSettings({
        username: user.username,
        apiKey: null,
        error,
        success,
        theme: req.session.theme || 'dark',
        isAdmin: req.session.isAdmin || false,
        dateFmt: req.session.dateFmt || 'dmy',
        localUrl: getSetting('local_url') || null,
        uploadMaxBytes: getSetting('upload_max_bytes') || '',
        uptime: getUptime(),
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce
    }));
}

function getUptime() {
    const up = Math.floor(process.uptime());
    const mins  = Math.floor((up % 3600) / 60);
    const hrs = Math.floor(up / 3600) % 24;
    const days  = Math.floor(up / 86400) % 30;
    const months = Math.floor(up / 2592000) % 12;
    const years = Math.floor(up / 31536000);
    const parts = [];
    if (years  > 0) parts.push(years  + 'y');
    if (months > 0) parts.push(months + 'mo');
    if (days   > 0) parts.push(days   + 'd');
    parts.push(hrs + 'h ' + String(mins).padStart(2, '0') + 'm');
    return parts.join(' ');
}

module.exports = function(app) {

app.get('/settings', requireSession, csrfProtection, (req, res) => {
    const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId);
    const apiKeyRow = db.prepare('SELECT api_key, label FROM api_keys WHERE user_id = ? LIMIT 1').get(user.id);
    
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderSettings({
        username: user.username,
        apiKey: null,
        error: null,
        success: null,
        theme: req.session.theme || 'dark',
        isAdmin: req.session.isAdmin || false,
        dateFmt: req.session.dateFmt || 'dmy',
        localUrl: getSetting('local_url') || null,
        uploadMaxBytes: getSetting('upload_max_bytes') || '',
        uptime: getUptime(),
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce
    }));
});

app.post('/settings/password', requireSession, csrfProtection, (req, res) => {
    const { current_password, new_password, confirm_password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    
    if (!bcrypt.compareSync(current_password || '', user.password_hash)) {
        return respondSettings(req, res, 'Current password is incorrect', null);
    }
    
    if (!new_password || !isStrongPassword(new_password)) {
        return respondSettings(req, res, 'Password must be at least 8 characters and contain uppercase, lowercase, a number, and a special character', null);
    }
    
    if (new_password !== confirm_password) {
        return respondSettings(req, res, 'New passwords do not match', null);
    }
    
    const hash = bcrypt.hashSync(new_password, 10);
    
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.session.userId);
    
    respondSettings(req, res, null, 'Password updated successfully');
});

app.post('/settings/theme', requireSession, csrfProtection, (req, res) => {
    const theme = (req.body && req.body.theme) || (req.query && req.query.theme);
    
    if (!['dark', 'light'].includes(theme)) {
        return res.status(400).json({ ok: false });
    }
    
    setUserTheme(req.session.userId, theme);
    req.session.theme = theme;
    res.json({ ok: true });
});

app.post('/settings/regen-key', requireSession, csrfProtection, (req, res) => {
    const { raw: newRaw, hash: newHash } = generateApiKey();
    const existing = db.prepare('SELECT id FROM api_keys WHERE user_id = ?').get(req.session.userId);
    
    if (existing) {
        db.prepare('UPDATE api_keys SET api_key = ? WHERE user_id = ?').run(newHash, req.session.userId);
    } else {
        db.prepare('INSERT INTO api_keys (user_id, api_key, label) VALUES (?,?,?)').run(req.session.userId, newHash, 'Default');
    }
    
    logSecurityEvent(getClientIp(req), `API key regenerated for user_id: ${req.session.userId}`);
    const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId);
    const apiKeyRow = db.prepare('SELECT api_key, label FROM api_keys WHERE user_id = ? LIMIT 1').get(user.id);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderSettings({
        username: user.username,
        apiKey: newRaw,
        uptime: getUptime(),
        error: null,
        success: 'New API key generated — copy it now and paste it into the Android app. It will not be shown again.',
        theme: req.session.theme || 'dark',
        isAdmin: req.session.isAdmin || false,
        dateFmt: req.session.dateFmt || 'dmy',
        localUrl: getSetting('local_url') || null,
        uploadMaxBytes: getSetting('upload_max_bytes') || '',
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce
    }));
});

app.post('/settings/dateformat', requireSession, csrfProtection, (req, res) => {
    const { date_format } = req.body;

    if (!['dmy', 'mdy'].includes(date_format)) {
        return res.redirect('/settings');
    }

    const oldFmt = req.session.dateFmt || 'dmy';
    let renameMsg = '';

    if (oldFmt !== date_format) {
        function convertDateStr(s) {
            const parts = s.split('.');
            if (parts.length !== 3) return null;
            return `${parts[1]}.${parts[0]}.${parts[2]}`;
        }

        const DATE_RE = /^\d{2}\.\d{2}\.\d{4}$/;

        const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.session.userId);
        const folders = db.prepare('SELECT name FROM folders WHERE user_id = ?').all(req.session.userId);

        let diskRenamed = 0;
        let diskSkipped = 0;

        for (const f of folders) {
            const syncDir = path.join(DATA_DIR, user.username, f.name);
            if (!fs.existsSync(syncDir)) continue;

            let entries;
            try { entries = fs.readdirSync(syncDir); } catch { continue; }

            for (const entry of entries) {
                if (!DATE_RE.test(entry)) continue;
                const converted = convertDateStr(entry);
                if (!converted || converted === entry) continue;

                const oldPath = path.join(syncDir, entry);
                const newPath = path.join(syncDir, converted);

                if (!fs.statSync(oldPath).isDirectory()) continue;

                if (fs.existsSync(newPath)) {
                    diskSkipped++;
                    continue;
                }

                try {
                    fs.renameSync(oldPath, newPath);
                    diskRenamed++;
                } catch (e) {
                    diskSkipped++;
                }
            }
        }

        const distinctDates = db.prepare(`
            SELECT DISTINCT date_folder
            FROM uploaded_files
            WHERE user_id = ?
        `).all(req.session.userId).map(r => r.date_folder);

        let dbUpdated = 0;

        const updateStmt = db.prepare(`
            UPDATE uploaded_files
            SET date_folder = ?
            WHERE user_id = ? AND date_folder = ?
        `);

        const updateAll = db.transaction(() => {
            for (const oldDate of distinctDates) {
                if (!DATE_RE.test(oldDate)) continue;
                const newDate = convertDateStr(oldDate);
                if (!newDate || newDate === oldDate) continue;
                const changes = updateStmt.run(newDate, req.session.userId, oldDate).changes;
                dbUpdated += changes;
            }
        });
        updateAll();

        const parts = [];
        if (diskRenamed > 0)
            parts.push(`${diskRenamed} date folder${diskRenamed !== 1 ? 's' : ''} on disk renamed`);
        if (diskSkipped > 0)
            parts.push(`${diskSkipped} skipped (target already exists)`);
        if (dbUpdated > 0)
            parts.push(`${dbUpdated} database record${dbUpdated !== 1 ? 's' : ''} updated`);

        if (parts.length > 0) {
            renameMsg = ` ${parts.join(', ')}.`;
        } else {
            renameMsg = ' No existing date folders found — only future uploads will use the new format.';
        }
    }

    setUserDateFmt(req.session.userId, date_format);
    req.session.dateFmt = date_format;
    respondSettings(req, res, null, `Date format changed to ${date_format === 'mdy' ? 'MM.DD.YYYY' : 'DD.MM.YYYY'}.${renameMsg}`);
});

app.post('/settings/upload-limit', requireAdmin, csrfProtection, (req, res) => {
    const gb = parseInt(req.body.upload_max_gb, 10);
    if (isNaN(gb) || gb < 0) return respondSettings(req, res, 'Invalid selection.', null);

    const bytes = gb > 0 ? String(gb * 1024 * 1024 * 1024) : '';
    setSetting('upload_max_bytes', bytes);
    respondSettings(req, res, null, gb > 0 ? `Upload limit set to ${gb} GB.` : 'Upload limit removed (unlimited).');
});

app.post('/settings/local-url', requireAdmin, csrfProtection, (req, res) => {
    const raw = req.body.clear_url ? '' : String(req.body.local_url || '').trim();
    
    if (raw && !raw.match(/^https?:\/\/.+/)) {
        return respondSettings(req, res, 'Invalid URL — must start with http:// or https://', null);
    }
    
    setSetting('local_url', raw);
    respondSettings(req, res, null, raw ? `Local URL saved: ${raw}` : 'Local URL cleared.');
});

app.get('/web/upload-status', requireSession, (req, res) => {
    res.json({ active: dbLib.activeUploads, lastUploadAt: dbLib.lastUploadAt });
});

app.post('/web/folders/remove', requireSession, csrfProtection, (req, res) => {
    const { name, delete_files } = req.body;
    const doFiles = delete_files === 'on';

    const folder = db.prepare('SELECT id FROM folders WHERE user_id = ? AND name = ?')
        .get(req.session.userId, name);

    if (folder) {
        db.prepare('DELETE FROM folders WHERE id = ?').run(folder.id);
    }

    if (doFiles) {
        const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.session.userId);
        const folderPath = path.join(DATA_DIR, user.username, name);
        if (fs.existsSync(folderPath)) {
            try {
                fs.rmSync(folderPath, { recursive: true, force: true });
            } catch (e) {
                console.error(`[DELETE FOLDER] Failed to remove ${folderPath}:`, e.message);
            }
        }
    }

    res.redirect('/');
});

};
