'use strict';

const bcrypt = require('bcryptjs');
const dbLib = require('../lib/db');
const { db, generateApiKey, isStrongPassword, safeName, runIntegrityCheck, DATA_DIR } = dbLib;
const { requireAdmin, requireSession, logSecurityEvent, getClientIp } = require('../lib/security');
const { renderUsersPage } = require('../views/templates');
const csrf = require('csurf');
const fs   = require('fs');
const path = require('path');

const csrfProtection = csrf({ cookie: false });

function getUptime() {
    const up = Math.floor(process.uptime());
    const mins = Math.floor((up % 3600) / 60);
    const hrs = Math.floor(up / 3600) % 24;
    const days = Math.floor(up / 86400) % 30;
    const months = Math.floor(up / 2592000) % 12;
    const years  = Math.floor(up / 31536000);
    const parts  = [];
    if (years  > 0) parts.push(years  + 'y');
    if (months > 0) parts.push(months + 'mo');
    if (days   > 0) parts.push(days   + 'd');
    parts.push(hrs + 'h ' + String(mins).padStart(2, '0') + 'm');
    return parts.join(' ');
}

module.exports = function(app) {

app.post('/users/unblock', requireAdmin, csrfProtection, (req, res) => {
    const { ip } = req.body;
    const theme = req.session.theme || 'dark';
    
    const users = () => db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
    const blocked = () => db.prepare('SELECT ip, blocked_at, reason, country, city FROM blocked_ips ORDER BY blocked_at DESC').all();
    const secEvts = () => db.prepare('SELECT ip, event, created_at FROM security_events ORDER BY created_at DESC LIMIT 100').all();
    
    if (!ip) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(), 
            secEvents: secEvts(),
            theme, 
            error: 'Missing IP.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    db.prepare('DELETE FROM blocked_ips WHERE ip = ?').run(ip);
    logSecurityEvent(getClientIp(req), `Admin unblocked IP: ${ip}`);
    console.log(`[SECURITY] Admin unblocked IP: ${ip}`);
    
    return res.send(renderUsersPage({ 
        users: users(), 
        blocked: blocked(), 
        secEvents: secEvts(),
        theme, 
        error: null, 
        success: `IP ${ip} has been unblocked.`,
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce
    }));
});

app.get('/users', requireAdmin, csrfProtection, (req, res) => {
    const users = db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
    const blocked = db.prepare('SELECT ip, blocked_at, reason, country, city FROM blocked_ips ORDER BY blocked_at DESC').all();
    const secEvents = db.prepare('SELECT ip, event, created_at FROM security_events ORDER BY created_at DESC LIMIT 100').all();
    const theme = req.session.theme || 'dark';
    
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderUsersPage({ 
        users, 
        blocked, 
        secEvents,
        theme, 
        error: null, 
        success: null, 
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce,
        uptime: getUptime()
    }));
});

app.post('/users/create', requireAdmin, csrfProtection, (req, res) => {
    const { username, password, confirm_password } = req.body;
    const theme = req.session.theme || 'dark';
    
    const users = () => db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
    const blocked = () => db.prepare('SELECT ip, blocked_at, reason, country, city FROM blocked_ips ORDER BY blocked_at DESC').all();
    const secEvts = () => db.prepare('SELECT ip, event, created_at FROM security_events ORDER BY created_at DESC LIMIT 100').all();
    
    if (!username || !safeName(username)) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'Invalid username. Use letters, numbers, dash, underscore or dot.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    if (!password || !isStrongPassword(password)) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'Password must be at least 8 characters and contain uppercase, lowercase, a number, and a special character.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    if (password !== confirm_password) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'Passwords do not match.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
    
    if (existing) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'Username already taken.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (username, password_hash, is_admin, must_change_password) VALUES (?, ?, 0, 0)')
        .run(username.trim(), hash);
    
    const { hash: apiKeyHash } = generateApiKey();
    db.prepare('INSERT INTO api_keys (user_id, api_key, label) VALUES (?, ?, ?)').run(result.lastInsertRowid, apiKeyHash, 'Default');
    
    return res.send(renderUsersPage({ 
        users: users(), 
        blocked: blocked(), 
            secEvents: secEvts(),
        theme, 
        error: null, 
        success: `User "${username.trim()}" created successfully.`,
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce
    }));
});

app.post('/users/delete', requireAdmin, csrfProtection, (req, res) => {
    const { user_id, delete_db, delete_files } = req.body;
    const theme = req.session.theme || 'dark';
    
    const users = () => db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
    const blocked = () => db.prepare('SELECT ip, blocked_at, reason, country, city FROM blocked_ips ORDER BY blocked_at DESC').all();
    const secEvts = () => db.prepare('SELECT ip, event, created_at FROM security_events ORDER BY created_at DESC LIMIT 100').all();
    
    if (!user_id) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'Missing user ID.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    const target = db.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').get(parseInt(user_id));
    
    if (!target) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'User not found.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    if (target.is_admin) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'Cannot delete the admin account.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    const doDb = delete_db === 'on' || delete_files === 'on';
    const doFiles = delete_files === 'on';
    
    if (doDb) {
        db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
    } else {
        const invalidHash = '$2a$10$invalid.hash.that.will.never.match.any.password.ever';
        db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?')
            .run(invalidHash, target.id);
        db.prepare('DELETE FROM api_keys WHERE user_id = ?').run(target.id);
    }
    
    if (doFiles) {
        const userDir = path.join(DATA_DIR, target.username);
        if (fs.existsSync(userDir)) {
            try {
                fs.rmSync(userDir, { recursive: true, force: true });
            } catch (e) {
                console.error(`[DELETE USER] Failed to remove directory ${userDir}:`, e.message);
            }
        }
    }
    
    const parts = ['User account deleted.'];
    if (doDb) parts.push('All database records removed.');
    if (doFiles) parts.push('All files deleted from disk.');
    if (!doDb && !doFiles) parts.push('Login access revoked. Data preserved on disk and in database.');
    
    return res.send(renderUsersPage({ 
        users: users(), 
        blocked: blocked(),
            secEvents: secEvts(), 
        theme, 
        error: null, 
        success: parts.join(' '),
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce
    }));
});

app.post('/users/change-password', requireAdmin, csrfProtection, (req, res) => {
    const { user_id, new_password, confirm_password } = req.body;
    const theme = req.session.theme || 'dark';
    
    const users = () => db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
    const blocked = () => db.prepare('SELECT ip, blocked_at, reason, country, city FROM blocked_ips ORDER BY blocked_at DESC').all();
    const secEvts = () => db.prepare('SELECT ip, event, created_at FROM security_events ORDER BY created_at DESC LIMIT 100').all();
    
    const target = db.prepare('SELECT id, username FROM users WHERE id = ?').get(parseInt(user_id));
    
    if (!target) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'User not found.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    if (!new_password || !isStrongPassword(new_password)) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'Password must be at least 8 characters and contain uppercase, lowercase, a number, and a special character.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    if (new_password !== confirm_password) {
        return res.send(renderUsersPage({ 
            users: users(), 
            blocked: blocked(),
            secEvents: secEvts(), 
            theme, 
            error: 'Passwords do not match.', 
            success: null, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce,
            uptime: getUptime()
        }));
    }
    
    const hash = bcrypt.hashSync(new_password, 10);
    
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, target.id);
    
    return res.send(renderUsersPage({ 
        users: users(), 
        blocked: blocked(), 
            secEvents: secEvts(),
        theme, 
        error: null, 
        success: `Password for "${target.username}" updated.`,
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce
    }));
});

app.post('/settings/integrity-check', requireSession, csrfProtection, (req, res) => {
    if (dbLib.activeUploads > 0) {
        return res.redirect('/?msg=' + encodeURIComponent('Integrity check skipped — an upload is in progress. Please try again once uploads have finished.'));
    }
    const result = runIntegrityCheck(req.session.userId);
    const msg = result.removed > 0
        ? `Integrity check complete. Checked ${result.checked} files, removed ${result.removed} missing entr${result.removed === 1 ? 'y' : 'ies'} from database.`
        : `Integrity check complete. All ${result.checked} file records are valid.`;
    
    res.redirect('/?msg=' + encodeURIComponent(msg));
});

app.post('/users/integrity-check', requireAdmin, csrfProtection, (req, res) => {
    if (dbLib.activeUploads > 0) {
        const users = db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
        const blocked = db.prepare('SELECT ip, blocked_at, reason, country, city FROM blocked_ips ORDER BY blocked_at DESC').all();
        const secEvents = db.prepare('SELECT ip, event, created_at FROM security_events ORDER BY created_at DESC LIMIT 100').all();
        return res.send(renderUsersPage({ users, blocked, secEvents, theme: req.session.theme || 'dark', error: 'Integrity check skipped — an upload is in progress. Please try again once uploads have finished.', success: null, csrfToken: req.csrfToken(), nonce: res.locals.cspNonce }));
    }
    const allUsers = db.prepare('SELECT id, username FROM users WHERE is_admin = 0').all();
    const results = allUsers.map(u => ({
        username: u.username,
        ...runIntegrityCheck(u.id)
    }));
    
    const totalChecked = results.reduce((a, r) => a + r.checked, 0);
    const totalRemoved = results.reduce((a, r) => a + r.removed, 0);
    
    const detail = results
        .map(r => `${r.username}: checked ${r.checked}, removed ${r.removed}`)
        .join(' · ');
    
    const msg = totalRemoved > 0
        ? `Integrity check complete. ${detail}. Total removed: ${totalRemoved}.`
        : `Integrity check complete. All ${totalChecked} file records across ${allUsers.length} user${allUsers.length === 1 ? '' : 's'} are valid.`;
    
    const users = db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all();
    const blocked = db.prepare('SELECT ip, blocked_at, reason, country, city FROM blocked_ips ORDER BY blocked_at DESC').all();
    const secEvents = db.prepare('SELECT ip, event, created_at FROM security_events ORDER BY created_at DESC LIMIT 100').all();
    const theme = req.session.theme || 'dark';
    
    return res.send(renderUsersPage({ 
        users, 
        blocked, 
        secEvents,
        theme, 
        error: null, 
        success: msg, 
        csrfToken: req.csrfToken(),
        nonce: res.locals.cspNonce
    }));
});

};
