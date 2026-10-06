'use strict';
/* ============================================================================
 * GATEKEEPER — secure ticket passes
 * ----------------------------------------------------------------------------
 * Every ticket gets a custom QR whose payload is:
 *
 *     GK1.<eventId>.<ticketId>.<HMAC-SHA256 signature>
 *
 * The HMAC is computed with a 256-bit secret that is generated on first run
 * and NEVER leaves the server. That means:
 *   - Nobody can forge a ticket without the server secret (cryptographically
 *     unforgeable — editing the QR by hand just fails signature verification).
 *   - Nobody can *verify* a ticket without the app, because only the app
 *     knows the secret. A generic QR scanner sees an opaque, meaningless string.
 *   - Each ticket is single-use: the server records the first scan, and every
 *     later scan is flagged ALREADY USED. Screenshots/copies of a valid ticket
 *     therefore only work once — first scan wins.
 *   - Only a logged-in host can create events/tickets or scan them in.
 *
 * Storage: a small atomic JSON database (data/db.json). Good for small and
 * medium events. For thousands of tickets at a big venue, swap in Postgres.
 * ========================================================================== */

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------- config ---
const PORT = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');
const SECRET_PATH = path.join(DATA_DIR, '.secret');
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const SESSION_COOKIE = 'gk_session';

fs.mkdirSync(DATA_DIR, { recursive: true });

// ------------------------------------------------- server-only secret -------
function loadOrCreateSecret() {
  try {
    if (fs.existsSync(SECRET_PATH)) {
      const s = fs.readFileSync(SECRET_PATH);
      if (s.length >= 32) return s;
    }
  } catch (e) { /* fall through and create */ }
  const s = crypto.randomBytes(32);
  fs.writeFileSync(SECRET_PATH, s, { mode: 0o600 });
  try { fs.chmodSync(SECRET_PATH, 0o600); } catch (e) {}
  return s;
}
const SIGNING_SECRET = loadOrCreateSecret();

// ------------------------------------------------------------- database ---
function blankDb() {
  return { host: null, events: [], tickets: [], sessions: {}, scans: [] };
}
function loadDb() {
  try {
    if (fs.existsSync(DB_PATH)) return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (e) { console.error('Could not read database, starting fresh:', e.message); }
  return blankDb();
}
function saveDb(db) {
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_PATH); // atomic: readers never see a half-written file
}
let db = loadDb();

// Purge expired sessions on boot and every hour.
function purgeSessions() {
  const now = Date.now();
  let changed = false;
  for (const [tok, s] of Object.entries(db.sessions)) {
    if (s.expiresAt < now) { delete db.sessions[tok]; changed = true; }
  }
  if (changed) saveDb(db);
}
purgeSessions();
setInterval(purgeSessions, 60 * 60 * 1000).unref();

// --------------------------------------------------------------- helpers ---
const rid = (n = 9) => crypto.randomBytes(n).toString('base64url'); // URL/QR-safe ids

function str(v, max, opts = {}) {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (!t && !opts.allowEmpty) return null;
  if (t.length > max) return null;
  return t;
}
function intIn(v, min, max) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n) || n < min || n > max) return null;
  return n;
}

// --- ticket signing: the heart of the anti-forgery design ---
function signTicket(eventId, ticketId) {
  return crypto.createHmac('sha256', SIGNING_SECRET)
    .update('GK1.' + eventId + '.' + ticketId)
    .digest('hex');
}
function ticketCode(eventId, ticketId) {
  return 'GK1.' + eventId + '.' + ticketId + '.' + signTicket(eventId, ticketId);
}
function verifyCode(code) {
  const m = /^GK1\.([A-Za-z0-9_-]{6,16})\.([A-Za-z0-9_-]{6,16})\.([a-f0-9]{64})$/
    .exec(String(code || '').trim());
  if (!m) return { ok: false, reason: 'bad_format' };
  const [, eventId, ticketId, sig] = m;
  const expected = signTicket(eventId, ticketId);
  const a = Buffer.from(sig, 'hex');
  const b = Buffer.from(expected, 'hex');
  // timingSafeEqual: no timing side-channel leaks about the signature
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'bad_signature' };
  }
  return { ok: true, eventId, ticketId };
}

// --- host password: scrypt, never stored in plain text ---
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64);
  return { salt: salt.toString('hex'), hash: hash.toString('hex'), algo: 'scrypt' };
}
function checkPassword(pw, rec) {
  try {
    const h = crypto.scryptSync(pw, Buffer.from(rec.salt, 'hex'), 64);
    return crypto.timingSafeEqual(h, Buffer.from(rec.hash, 'hex'));
  } catch (e) { return false; }
}

// --- login rate limiting: slow down password guessing ---
const loginAttempts = new Map(); // ip -> { fails, lockUntil }
function loginAllowed(ip) {
  const r = loginAttempts.get(ip);
  if (!r) return true;
  if (r.lockUntil && r.lockUntil > Date.now()) return false;
  return true;
}
function loginFailed(ip) {
  const r = loginAttempts.get(ip) || { fails: 0, lockUntil: 0 };
  r.fails += 1;
  if (r.fails >= 5) { r.lockUntil = Date.now() + 5 * 60 * 1000; r.fails = 0; }
  loginAttempts.set(ip, r);
}
function loginOk(ip) { loginAttempts.delete(ip); }

// --- public (safe to send to the host's browser) projections ---
function pubTicket(t) {
  return {
    id: t.id, eventId: t.eventId, type: t.type, holder: t.holder || '',
    code: ticketCode(t.eventId, t.id),
    usedAt: t.usedAt || null, revoked: !!t.revoked, createdAt: t.createdAt
  };
}
function pubEvent(e) {
  return { id: e.id, name: e.name, date: e.date || '', venue: e.venue || '', notes: e.notes || '', createdAt: e.createdAt };
}
function logScan(ticketId, status) {
  db.scans.unshift({ id: rid(6), ticketId: ticketId || null, status, at: new Date().toISOString() });
  db.scans = db.scans.slice(0, 200); // keep the log bounded
  saveDb(db);
}

// ------------------------------------------------------------------ app ---
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '5mb' })); // 5mb so full database restores fit

// Basic hardening headers.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(self)');
  next();
});

function getSession(req) {
  const cookie = req.headers.cookie || '';
  const m = /(?:^|;\s*)gk_session=([^;]+)/.exec(cookie);
  if (!m) return null;
  const s = db.sessions[m[1]];
  if (!s || s.expiresAt < Date.now()) return null;
  return { token: m[1], ...s };
}
function requireAuth(req, res, next) {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: 'Host login required.' });
  req.session = s;
  next();
}
function setSessionCookie(res, token) {
  // httpOnly: page JavaScript can never read the session token (XSS-resistant).
  // SameSite=Lax: the cookie is never sent on cross-site requests (CSRF-resistant).
  res.setHeader('Set-Cookie',
    `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

// ------------------------------------------------------------- auth API ---
app.get('/api/status', (req, res) => {
  res.json({ setupNeeded: !db.host, loggedIn: !!getSession(req) });
});

app.post('/api/setup', (req, res) => {
  if (db.host) return res.status(400).json({ error: 'Host account already exists. Log in instead.' });
  const pw = str(req.body && req.body.password, 128);
  if (!pw || pw.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  db.host = hashPassword(pw);
  const token = rid(24);
  db.sessions[token] = { createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS };
  saveDb(db);
  setSessionCookie(res, token);
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const ip = req.ip || 'unknown';
  if (!db.host) return res.status(400).json({ error: 'No host account yet. Set one up first.' });
  if (!loginAllowed(ip)) return res.status(429).json({ error: 'Too many failed attempts. Try again in 5 minutes.' });
  const pw = str(req.body && req.body.password, 128, { allowEmpty: true }) || '';
  // Constant-ish work even for wrong passwords (scrypt dominates anyway).
  if (!checkPassword(pw, db.host)) {
    loginFailed(ip);
    return res.status(401).json({ error: 'Wrong password.' });
  }
  loginOk(ip);
  const token = rid(24);
  db.sessions[token] = { createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS };
  saveDb(db);
  setSessionCookie(res, token);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const s = getSession(req);
  if (s) { delete db.sessions[s.token]; saveDb(db); }
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ ok: true, role: 'host' }));

// ------------------------------------------------------------ events API ---
app.get('/api/events', requireAuth, (req, res) => {
  res.json({ events: db.events.map(pubEvent) });
});

app.post('/api/events', requireAuth, (req, res) => {
  const name = str(req.body && req.body.name, 120);
  if (!name) return res.status(400).json({ error: 'Event name is required.' });
  const date = str(req.body.date, 40, { allowEmpty: true }) || '';
  const venue = str(req.body.venue, 160, { allowEmpty: true }) || '';
  const notes = str(req.body.notes, 500, { allowEmpty: true }) || '';
  const e = { id: rid(8), name, date, venue, notes, createdAt: new Date().toISOString() };
  db.events.unshift(e);
  saveDb(db);
  res.json({ event: pubEvent(e) });
});

app.delete('/api/events/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const i = db.events.findIndex(e => e.id === id);
  if (i < 0) return res.status(404).json({ error: 'Event not found.' });
  db.events.splice(i, 1);
  db.tickets = db.tickets.filter(t => t.eventId !== id);
  saveDb(db);
  res.json({ ok: true });
});

// ------------------------------------------------------------ tickets API ---
app.get('/api/events/:id/tickets', requireAuth, (req, res) => {
  const id = String(req.params.id);
  if (!db.events.some(e => e.id === id)) return res.status(404).json({ error: 'Event not found.' });
  const tickets = db.tickets.filter(t => t.eventId === id).map(pubTicket);
  res.json({ tickets });
});

app.post('/api/events/:id/tickets', requireAuth, (req, res) => {
  const id = String(req.params.id);
  if (!db.events.some(e => e.id === id)) return res.status(404).json({ error: 'Event not found.' });
  const count = intIn(req.body && req.body.count, 1, 500);
  const type = str(req.body && req.body.type, 60) || 'General';
  const holder = str(req.body && req.body.holder, 120, { allowEmpty: true }) || '';
  if (!count) return res.status(400).json({ error: 'Count must be between 1 and 500.' });
  const now = new Date().toISOString();
  const made = [];
  for (let i = 0; i < count; i++) {
    const t = {
      id: rid(9), eventId: id, type,
      holder: count === 1 ? holder : '',
      usedAt: null, revoked: false, createdAt: now
    };
    db.tickets.push(t);
    made.push(pubTicket(t));
  }
  saveDb(db);
  res.json({ tickets: made });
});

app.patch('/api/tickets/:id', requireAuth, (req, res) => {
  const t = db.tickets.find(x => x.id === String(req.params.id));
  if (!t) return res.status(404).json({ error: 'Ticket not found.' });
  if (typeof req.body.revoked === 'boolean') t.revoked = req.body.revoked;
  const holder = str(req.body.holder, 120, { allowEmpty: true });
  if (holder !== null) t.holder = holder;
  saveDb(db);
  res.json({ ticket: pubTicket(t) });
});

app.delete('/api/tickets/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const i = db.tickets.findIndex(x => x.id === id);
  if (i < 0) return res.status(404).json({ error: 'Ticket not found.' });
  db.tickets.splice(i, 1);
  saveDb(db);
  res.json({ ok: true });
});

// ------------------------------------------------- verification (the gate) ---
// Host-only: only this app, logged in as host, can ask "is this ticket real?"
app.post('/api/verify', requireAuth, (req, res) => {
  const v = verifyCode(req.body && req.body.payload);
  if (!v.ok) {
    logScan(null, 'invalid');
    return res.json({ status: 'invalid', reason: v.reason === 'bad_signature' ? 'forged_or_tampered' : 'not_a_ticket' });
  }
  const t = db.tickets.find(x => x.id === v.ticketId && x.eventId === v.eventId);
  if (!t) { logScan(null, 'invalid'); return res.json({ status: 'invalid', reason: 'unknown_ticket' }); }
  const ev = db.events.find(e => e.id === t.eventId);
  if (!ev) { logScan(t.id, 'invalid'); return res.json({ status: 'invalid', reason: 'event_deleted' }); }
  if (t.revoked) { logScan(t.id, 'revoked'); return res.json({ status: 'revoked', ticket: pubTicket(t), event: pubEvent(ev) }); }
  if (t.usedAt) {
    logScan(t.id, 'already_used');
    return res.json({ status: 'already_used', ticket: pubTicket(t), event: pubEvent(ev) });
  }
  t.usedAt = new Date().toISOString(); // single-use: first scan wins
  saveDb(db);
  logScan(t.id, 'valid');
  res.json({ status: 'valid', ticket: pubTicket(t), event: pubEvent(ev) });
});

app.get('/api/scans', requireAuth, (req, res) => {
  const limit = intIn(req.query.limit, 1, 100) || 20;
  res.json({ scans: db.scans.slice(0, limit) });
});

app.get('/api/stats', requireAuth, (req, res) => {
  const used = db.tickets.filter(t => t.usedAt).length;
  res.json({
    events: db.events.length,
    tickets: db.tickets.length,
    checkedIn: used,
    scansToday: db.scans.filter(s => s.at.slice(0, 10) === new Date().toISOString().slice(0, 10)).length
  });
});

// ------------------------------------------------- backup & restore ---
// One-click safety net: download the whole database (host, events, tickets)
// as JSON, and restore it later. Essential before redeploying on hosts with
// an ephemeral filesystem (e.g. free-tier hosting without a persistent disk).
app.get('/api/backup', requireAuth, (req, res) => {
  res.json({
    app: 'gatekeeper', version: 1, exportedAt: new Date().toISOString(),
    data: { host: db.host, events: db.events, tickets: db.tickets }
  });
});

app.post('/api/restore', requireAuth, (req, res) => {
  const d = req.body && req.body.data;
  if (!d || typeof d !== 'object') return res.status(400).json({ error: 'Invalid backup file.' });
  if (!d.host || typeof d.host !== 'object' || !Array.isArray(d.events) || !Array.isArray(d.tickets)) {
    return res.status(400).json({ error: 'Backup is missing host, events, or tickets.' });
  }
  if (d.events.length > 10000 || d.tickets.length > 50000) {
    return res.status(400).json({ error: 'Backup too large.' });
  }
  // Sessions are intentionally dropped: everyone must log in again after a restore.
  db = { host: d.host, events: d.events, tickets: d.tickets, sessions: {}, scans: [] };
  saveDb(db);
  res.json({ ok: true, events: d.events.length, tickets: d.tickets.length });
});

// ---------------------------------------------------------------- static ---
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log(`Gatekeeper running → http://localhost:${PORT}`);
  if (!db.host) console.log('First run: open the page and create your host password.');
});
