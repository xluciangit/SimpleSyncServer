'use strict';

const { db, getUserTheme, getUserDateFmt, isStrongPassword } = require('../lib/db');
const { logSecurityEvent, getClientIp, loginLimiter, loginFailures, requireSession } = require('../lib/security');
const { renderLogin, renderChangePassword } = require('../views/templates');
const bcrypt = require('bcryptjs');
const csrf = require('csurf');

const csrfProtection = csrf({ cookie: false });

module.exports = function(app) {

app.get('/login', csrfProtection, (req, res) => {
    if (req.session.userId) return res.redirect('/');
    const theme = req.cookies?.sss_theme || 'dark';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderLogin({ error: null, csrfToken: req.csrfToken(), nonce: res.locals.cspNonce, theme }));
});

let globalLoginAttempts = 0;
setInterval(() => { globalLoginAttempts = 0; }, 5 * 60 * 1000).unref();

app.post('/login', loginLimiter, csrfProtection, async (req, res) => {
    if (++globalLoginAttempts > 200) {
        return res.status(429).send('Too many login attempts. Please try again later.');
    }

    await new Promise(r => setTimeout(r, Math.random() * 500));

    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.send(renderLogin({ 
            error: 'Username and password are required', 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce
        }));
    }
    
    const uname = username.trim().toLowerCase();

    const fail = loginFailures.get(uname);
    if (fail) {
        const delayMs = Math.min(2000 * fail.count, 20000);
        await new Promise(r => setTimeout(r, delayMs));
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());

    if (user && user.locked_until && Date.now() < user.locked_until) {
        const remaining = Math.ceil((user.locked_until - Date.now()) / 60000);
        return res.send(renderLogin({
            error: `Account locked due to too many failed attempts. Try again in ${remaining} minute${remaining !== 1 ? 's' : ''}.`,
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce
        }));
    }
    
    const fakeHash = '$2a$10$dummyhashfortimingnobodywilleverusethisXXXXXXXXXXXXXXXX';
    const passwordMatches = bcrypt.compareSync(password, user ? user.password_hash : fakeHash);
    
    if (!user || !passwordMatches) {
        const entry = loginFailures.get(uname) || { count: 0 };
        entry.count++;
        loginFailures.set(uname, entry);

        if (user && entry.count >= 10) {
            const lockUntil = Date.now() + 30 * 60 * 1000;
            db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(lockUntil, user.id);
            logSecurityEvent(getClientIp(req), `Account locked: ${uname} (${entry.count} failures)`);
        } else {
            logSecurityEvent(getClientIp(req), `Failed login: ${uname}`);
        }

        return res.send(renderLogin({ 
            error: 'Invalid username or password', 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce
        }));
    }

    loginFailures.delete(uname);
    if (user.locked_until) {
        db.prepare('UPDATE users SET locked_until = 0 WHERE id = ?').run(user.id);
    }

    req.session.regenerate((err) => {
        if (err) {
            return res.send(renderLogin({ 
                error: 'Login failed, please try again.', 
                csrfToken: req.csrfToken(),
                nonce: res.locals.cspNonce
            }));
        }
        
        logSecurityEvent(getClientIp(req), `Successful login: ${user.username}`);
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.isAdmin = user.is_admin === 1;
        req.session.mustChangePassword = user.must_change_password === 1;
        req.session.theme = getUserTheme(user.id);
        req.session.dateFmt = getUserDateFmt(user.id);
        
        if (user.must_change_password) return res.redirect('/change-password');
        if (user.is_admin) return res.redirect('/users');
        
        res.redirect('/');
    });
});

app.post('/logout', csrfProtection, (req, res) => {
    const theme = req.session.theme || 'dark';
    req.session.destroy(() => {
        res.cookie('sss_theme', theme, { maxAge: 365 * 24 * 3600 * 1000, httpOnly: false, sameSite: 'lax' });
        res.redirect('/login');
    });
});

app.get('/change-password', csrfProtection, (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderChangePassword({ 
        error: null, 
        isFirstTime: req.session.mustChangePassword, 
        csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce 
    }));
});

app.post('/change-password', csrfProtection, (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    
    const { new_password, confirm_password } = req.body;
    
    if (!new_password || !isStrongPassword(new_password)) {
        return res.send(renderChangePassword({ 
            error: 'Password must be at least 8 characters and contain uppercase, lowercase, a number, and a special character', 
            isFirstTime: req.session.mustChangePassword, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce 
        }));
    }
    
    if (new_password !== confirm_password) {
        return res.send(renderChangePassword({ 
            error: 'Passwords do not match', 
            isFirstTime: req.session.mustChangePassword, 
            csrfToken: req.csrfToken(),
            nonce: res.locals.cspNonce 
        }));
    }
    
    const hash = bcrypt.hashSync(new_password, 10);
    
    db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?')
        .run(hash, req.session.userId);
    
    req.session.mustChangePassword = false;
    res.redirect('/');
});

};
