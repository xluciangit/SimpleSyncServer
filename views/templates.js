'use strict';

const path = require('path');
const ejs  = require('ejs');
const { fmtBytes, VERSION } = require('../lib/db');

const VIEWS_DIR = path.join(__dirname);

function render(template, data) {
    return ejs.renderFile(
        path.join(VIEWS_DIR, template + '.ejs'),
        { ...data, fmtBytes, VERSION },
        { views: [VIEWS_DIR] }
    );
}

async function renderLogin(res, data) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(await render('login', data));
}

async function renderChangePassword(res, data) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(await render('change-password', data));
}

async function renderDashboard(res, data) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(await render('dashboard', data));
}

async function renderSettings(res, data) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(await render('settings', data));
}

async function renderUsersPage(res, data) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(await render('users', data));
}

module.exports = { renderLogin, renderChangePassword, renderDashboard, renderSettings, renderUsersPage };
