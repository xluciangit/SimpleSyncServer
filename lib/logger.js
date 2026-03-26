'use strict';

const fs   = require('fs');
const path = require('path');

let _dataDir = null;
let _fmtBytes = null;
let _lookupGeoIp = null;

function init(dataDir, fmtBytes, lookupGeoIp) {
    _dataDir    = dataDir;
    _fmtBytes   = fmtBytes;
    _lookupGeoIp = lookupGeoIp;
}

function logDir(username) {
    return path.join(_dataDir, username, 'logs');
}

function logFilePath(username) {
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return path.join(logDir(username), `${y}-${m}-${day}.log`);
}

function ts() {
    return new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function write(username, line) {
    try {
        const dir = logDir(username);
        fs.mkdirSync(dir, { recursive: true });
        fs.appendFileSync(logFilePath(username), `[${ts()}]  ${line}\n`);
        console.log(`[${ts()}]  ${username}  |  ${line}`);
    } catch (e) {
        console.error('[LOGGER] write failed:', e.message, '| dataDir:', _dataDir, '| user:', username);
    }
}

function pruneUser(username) {
    try {
        const dir = logDir(username);
        if (!fs.existsSync(dir)) return;
        const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
        for (const f of fs.readdirSync(dir)) {
            if (!/^\d{4}-\d{2}-\d{2}\.log$/.test(f)) continue;
            const p = path.join(dir, f);
            try {
                if (fs.statSync(p).mtimeMs < cutoff) fs.unlinkSync(p);
            } catch {}
        }
    } catch {}
}

function pruneAll() {
    try {
        for (const entry of fs.readdirSync(_dataDir, { withFileTypes: true })) {
            if (entry.isDirectory() && !entry.name.startsWith('.')) {
                pruneUser(entry.name);
            }
        }
    } catch {}
}

function startPruner() {
    pruneAll();
    setInterval(pruneAll, 24 * 60 * 60 * 1000).unref();
}

const syncSessions = new Map();
const SESSION_TIMEOUT_MS = 30_000;

function trackUpload(username, userId, folder, fileSize, isWhatsApp) {
    const key = `${userId}:${isWhatsApp ? '__wa__' : folder}`;
    let s = syncSessions.get(key);

    if (!s) {
        const label = isWhatsApp ? 'WhatsApp folder' : `folder "${folder}"`;
        write(username, `Sync started  —  ${label}`);
        s = { username, folder: isWhatsApp ? 'WhatsApp' : folder, isWhatsApp, count: 0, bytes: 0 };
        syncSessions.set(key, s);
    } else {
        clearTimeout(s.timer);
    }

    s.count++;
    s.bytes += fileSize || 0;

    s.timer = setTimeout(() => {
        syncSessions.delete(key);
        const label = s.isWhatsApp ? 'WhatsApp folder' : `folder "${s.folder}"`;
        const size  = _fmtBytes ? _fmtBytes(s.bytes) : `${s.bytes} B`;
        write(s.username, `Sync completed  —  ${label}  ·  ${s.count} file${s.count !== 1 ? 's' : ''}  ·  ${size}`);
    }, SESSION_TIMEOUT_MS);
}

function logUploadFailed(username, folder, filename, reason) {
    const label = folder === 'WhatsApp' ? 'WhatsApp folder' : `folder "${folder}"`;
    const detail = reason ? `  (${reason})` : '';
    write(username, `Upload failed  —  ${label}  ·  ${filename}${detail}`);
}

async function logLogin(username, ip, success) {
    try {
        const geo   = _lookupGeoIp ? await _lookupGeoIp(ip).catch(() => ({})) : {};
        const loc   = [geo.city, geo.country].filter(Boolean).join(', ') || ip;
        const verb  = success ? 'Login succeeded' : 'Login failed';
        write(username, `${verb}  —  ${username}  ·  IP ${ip}  ·  ${loc}`);
    } catch {}
}

module.exports = { init, startPruner, trackUpload, logUploadFailed, logLogin, write };