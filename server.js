require('dotenv').config();

const express = require('express');
const mariadb = require('mariadb');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');

const app = express();
const port = Number(process.env.PORT) || 3000;
const scryptAsync = promisify(crypto.scrypt);
const sessionDurationSeconds = 8 * 60 * 60;
const sessions = new Map();
const database = mariadb.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'clogdetection',
    connectionLimit: 5
});

const publicFiles = new Set([
    'alerts.html',
    'analytics.html',
    'locations.html',
    'login.html',
    'overview.html',
    'role-routing.js',
    'settings.html',
    'settingsDRRM.html',
    'styles.css',
    'telemetry.html'
]);
const dashboardPages = new Set([
    'alerts.html',
    'analytics.html',
    'locations.html',
    'overview.html',
    'settings.html',
    'settingsDRRM.html',
    'telemetry.html'
]);

app.use(express.json({ limit: '16kb' }));

function timingSafeTextEqual(first, second) {
    const firstBuffer = Buffer.from(first);
    const secondBuffer = Buffer.from(second);
    return firstBuffer.length === secondBuffer.length
        && crypto.timingSafeEqual(firstBuffer, secondBuffer);
}

async function verifyPassword(password, storedPassword) {
    if (!storedPassword.startsWith('scrypt$')) {
        return timingSafeTextEqual(password, storedPassword);
    }

    const [, salt, hash] = storedPassword.split('$');
    if (!salt || !hash || !/^[a-f0-9]+$/i.test(hash)) return false;

    const expected = Buffer.from(hash, 'hex');
    const actual = await scryptAsync(password, salt, expected.length);
    return expected.length > 0 && crypto.timingSafeEqual(actual, expected);
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await scryptAsync(password, salt, 64);
    return `scrypt$${salt}$${hash.toString('hex')}`;
}

function getSessionId(request) {
    const cookie = (request.headers.cookie || '').split(';')
        .map((value) => value.trim())
        .find((value) => value.startsWith('clog_session='));
    return cookie ? decodeURIComponent(cookie.slice('clog_session='.length)) : null;
}

function getActiveSession(request) {
    const sessionId = getSessionId(request);
    const session = sessionId ? sessions.get(sessionId) : null;

    if (!session || session.expiresAt <= Date.now()) {
        if (sessionId) sessions.delete(sessionId);
        return null;
    }

    return session;
}

function requireRole(role) {
    return (request, response, next) => {
        const session = getActiveSession(request);

        if (!session) {
            return response.status(401).json({ error: 'Please sign in to continue.' });
        }

        if (session.role !== role) {
            return response.status(403).json({ error: 'You are not authorized to access this resource.' });
        }

        request.auth = session;
        next();
    };
}

app.post('/api/login', async (request, response, next) => {
    const username = typeof request.body?.username === 'string' ? request.body.username.trim() : '';
    const password = typeof request.body?.password === 'string' ? request.body.password : '';
    const requestedRole = typeof request.body?.role === 'string' ? request.body.role : '';

    if (!username || !password || username.length > 50 || password.length > 1024) {
        return response.status(400).json({ error: 'Enter a valid username and password.' });
    }

    try {
        const accounts = await database.query(
            `SELECT account_id, personnel_id, password_hash, role
            FROM Account
            WHERE username = ?
            LIMIT 1`,
            [username]
        );
        const account = accounts[0];

        if (!account || !(await verifyPassword(password, account.password_hash))) {
            return response.status(401).json({ error: 'Invalid username or password.' });
        }

        if (account.role !== requestedRole || !['Admin', 'DRRM Officer'].includes(account.role)) {
            return response.status(403).json({ error: 'The selected role does not match this account.' });
        }

        if (!account.password_hash.startsWith('scrypt$')) {
            const upgradedHash = await hashPassword(password);
            await database.query(
                'UPDATE Account SET password_hash = ? WHERE account_id = ?',
                [upgradedHash, account.account_id]
            );
        }

        const sessionId = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + sessionDurationSeconds * 1000;
        sessions.set(sessionId, {
            accountId: account.account_id,
            personnelId: account.personnel_id,
            role: account.role,
            expiresAt
        });

        const secureCookie = process.env.COOKIE_SECURE === 'true' ? '; Secure' : '';
        response.setHeader(
            'Set-Cookie',
            `clog_session=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionDurationSeconds}${secureCookie}`
        );
        response.json({ role: account.role });
    } catch (error) {
        next(error);
    }
});

app.post('/api/logout', (request, response) => {
    const sessionId = getSessionId(request);
    if (sessionId) sessions.delete(sessionId);
    response.setHeader('Set-Cookie', 'clog_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    response.status(204).end();
});

app.get('/api/health', async (request, response, next) => {
    try {
        await database.query('SELECT 1');
        response.json({ status: 'ok', database: process.env.DB_NAME || 'clogdetection' });
    } catch (error) {
        next(error);
    }
});

app.post('/api/account-requests', requireRole('DRRM Officer'), async (request, response, next) => {
    const body = request.body || {};
    const clean = (value, maxLength) => typeof value === 'string'
        ? value.trim().slice(0, maxLength) || null
        : null;

    const requestedName = clean(body.requestedName, 150);
    const requestedRole = clean(body.requestedRole, 100);
    const requestedContact = clean(body.requestedContact, 40);
    const requestedEmail = clean(body.requestedEmail, 254);
    const changeReason = clean(body.changeReason, 2000);
    const passwordReset = body.passwordReset === true;
    const hasProfileChanges = Boolean(
        requestedName || requestedRole || requestedContact || requestedEmail
    );

    if (!hasProfileChanges && !passwordReset) {
        return response.status(400).json({ error: 'Enter a profile change or request a password reset.' });
    }

    if (requestedEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(requestedEmail)) {
        return response.status(400).json({ error: 'Enter a valid requested email address.' });
    }

    try {
        const personnel = await database.query(
            `SELECT full_name AS requesterName, role AS requesterRole, contact_number AS requesterContact
            FROM Personnel
            WHERE personnel_id = ?
            LIMIT 1`,
            [request.auth.personnelId]
        );
        const requester = personnel[0] || {};
        const requesterName = clean(requester.requesterName, 150) || 'DRRM Officer';
        const requesterRole = clean(requester.requesterRole, 100) || request.auth.role;
        const requesterContact = clean(requester.requesterContact, 40);

        const result = await database.query(
            `INSERT INTO account_request (
                requester_name, requester_role, requester_contact,
                requested_name, requested_role, requested_contact, requested_email,
                change_reason, password_reset_requested
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                requesterName, requesterRole, requesterContact,
                requestedName, requestedRole, requestedContact, requestedEmail,
                changeReason, passwordReset
            ]
        );

        response.status(201).json({
            id: Number(result.insertId),
            status: 'pending',
            message: 'Request submitted.'
        });
    } catch (error) {
        next(error);
    }
});

app.get('/api/account-requests', requireRole('Admin'), async (request, response, next) => {
    try {
        const rows = await database.query(
            `SELECT
                id,
                requester_name AS currentName,
                requester_role AS currentRole,
                requester_contact AS currentContact,
                requested_name AS requestedName,
                requested_role AS requestedRole,
                requested_contact AS requestedContact,
                requested_email AS requestedEmail,
                change_reason AS changeReason,
                password_reset_requested AS passwordReset,
                status,
                submitted_at AS submittedAt
            FROM account_request
            ORDER BY submitted_at DESC, id DESC
            LIMIT 100`
        );

        response.json({ requests: rows });
    } catch (error) {
        next(error);
    }
});

app.get('/', (request, response) => {
    response.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/:file', (request, response, next) => {
    if (!publicFiles.has(request.params.file)) return next();

    if (dashboardPages.has(request.params.file)) {
        const session = getActiveSession(request);
        if (!session) return response.redirect('/login.html');

        const pageRole = request.params.file === 'settings.html'
            ? 'Admin'
            : request.params.file === 'settingsDRRM.html'
                ? 'DRRM Officer'
                : null;

        if (pageRole && session.role !== pageRole) {
            return response.status(403).send('Your account is not authorized to view this page.');
        }
    }

    response.sendFile(path.join(__dirname, request.params.file));
});

app.use((request, response) => {
    response.status(404).json({ error: 'Not found.' });
});

app.use((error, request, response, next) => {
    console.error(error);
    response.status(500).json({ error: 'The server could not complete the request.' });
});

app.listen(port, '127.0.0.1', () => {
    console.log(`Clog Detection System running at http://127.0.0.1:${port}`);
});