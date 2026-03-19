'use strict';

const { db, hashApiKey } = require('./db');

function getClientIp(req) {
    return req.ip;
}

function isIpBlocked(ip) {
    return !!db.prepare('SELECT ip FROM blocked_ips WHERE ip = ?').get(ip);
}

async function lookupGeoIp(ip) {
    try {
        const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,city,query`, {
            signal: AbortSignal.timeout(3000)
        });
        if (!res.ok) return { country: null, city: null };
        const data = await res.json();
        return { country: data.country || null, city: data.city || null };
    } catch (_) {
        return { country: null, city: null };
    }
}

function blockIp(ip) {
    db.prepare(`
        INSERT OR IGNORE INTO blocked_ips (ip, blocked_at, reason)
        VALUES (?, datetime('now'), 'Too many failed login attempts')
    `).run(ip);
    logSecurityEvent(ip, 'IP permanently blocked — too many rate limit violations');
    console.warn(`[SECURITY] Permanently blocked IP: ${ip}`);

    lookupGeoIp(ip).then(({ country, city }) => {
        if (country || city) {
            db.prepare('UPDATE blocked_ips SET country = ?, city = ? WHERE ip = ?').run(country, city, ip);
            console.warn(`[SECURITY] Geo updated for ${ip}: ${city || 'unknown city'}, ${country}`);
        }
    }).catch(() => {});
}

function logSecurityEvent(ip, event) {
    try {
        db.prepare('INSERT INTO security_events (ip, event) VALUES (?, ?)').run(ip || 'unknown', event);
    } catch (_) {}
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
        
        if (hits.size > 50000) {
            const evictCount = Math.floor(hits.size * 0.1);
            let evicted = 0;
            for (const key of hits.keys()) {
                hits.delete(key);
                if (++evicted >= evictCount) break;
            }
        }
        
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

const loginLimiter = makeRateLimiter({ windowMs: 5 * 60 * 1000, max: 20, message: 'Too many login attempts, please try again in 5 minutes.' });

const loginFailures = new Map();
setInterval(() => loginFailures.clear(), 60 * 60 * 1000).unref();
const apiLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 5000, message: 'Too many requests, please slow down.' });


function requireSession(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    
    if (req.session.mustChangePassword && req.path !== '/change-password') {
        return res.redirect('/change-password');
    }
    
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    if (!req.session.isAdmin) return res.status(403).send('Forbidden');
    next();
}

async function apiAuth(req, res, next) {
    const key = req.headers['x-api-key'] || req.query.apiKey;
    
    if (!key) return res.status(401).json({ error: 'Missing API key' });
    
    const keyHash = hashApiKey(key);
    const row = db.prepare(`
        SELECT ak.user_id, u.username, u.is_admin 
        FROM api_keys ak 
        JOIN users u ON u.id = ak.user_id 
        WHERE ak.api_key = ?
    `).get(keyHash);
    
    if (!row) {
        await new Promise(r => setTimeout(r, 300));
        return res.status(401).json({ error: 'Invalid API key' });
    }
    
    if (row.is_admin) return res.status(403).json({ error: 'Admin account cannot upload files' });
    
    req.apiUserId = row.user_id;
    req.apiUsername = row.username;
    next();
}


function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

module.exports = { getClientIp, isIpBlocked, blockIp, logSecurityEvent,
    makeRateLimiter, loginLimiter, loginFailures, apiLimiter,
    requireSession, requireAdmin, apiAuth, escapeHtml };
