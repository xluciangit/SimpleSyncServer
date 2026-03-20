'use strict';

const crypto = require('crypto');

function csrfMiddleware(req, res, next) {
    if (!req.session.csrfSecret) {
        req.session.csrfSecret = crypto.randomBytes(24).toString('hex');
    }

    const safe = ['GET', 'HEAD', 'OPTIONS'];
    if (!safe.includes(req.method)) {
        const token = req.body._csrf || req.headers['x-csrf-token'];
        if (!token || !verify(req.session.csrfSecret, token)) {
            return res.status(403).send('Form session expired or invalid. Please go back and try again.');
        }
    }
    next();
}

function generateToken(req) {
    const secret = req.session.csrfSecret;
    if (!secret) throw new Error('CSRF middleware must run before generateToken');
    const salt = crypto.randomBytes(8).toString('hex');
    const mac  = crypto.createHmac('sha256', secret).update(salt).digest('hex');
    return `${salt}.${mac}`;
}

function verify(secret, token) {
    const parts = typeof token === 'string' ? token.split('.') : [];
    if (parts.length !== 2) return false;
    const [salt, mac] = parts;
    const expected = crypto.createHmac('sha256', secret).update(salt).digest('hex');
    try {
        return crypto.timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
        return false;
    }
}

module.exports = { csrfProtection: csrfMiddleware, generateToken };
