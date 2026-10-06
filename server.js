'use strict';
/* ============================================================================
 * GATEKEEPER v2 — secure ticket passes, serverless edition (Vercel)
 * ----------------------------------------------------------------------------
 * Every ticket gets a custom QR whose payload is:
 *
 *     GK1.<eventId>.<ticketId>.<HMAC-SHA256 signature>
 *
 * The HMAC uses a secret from the GATEKEEPER_SECRET env var that NEVER leaves
 * the server: tickets are unforgeable, and only this app can verify them.
 * Passes are single-use (atomic SET NX claim — only one scan can win), and
 * every management/verification endpoint requires the host login.
 *
 * State lives in Vercel KV (Redis); serverless functions are stateless, so
 * there is no filesystem database. Set GK_MEMORY_STORE=1 for an in-memory
 * backend (local dev / tests, no network needed).
 * ========================================================================== */

if (!process.env.VERCEL) {
  try { require('dotenv').config(); } catch (e) { /* dotenv optional */ }
}

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const store = require('./store');

const IS_VERCEL = !!process.env.VERCEL;
const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_COOKIE = 'gk_session';
const SESSION_TTL_MS = store.SESSION_TTL_SEC * 1000;

// ------------------------------------------------- server-only secret -------
function getSecret() {
  const hex = (process.env.GATEKEEPER_SECRET || '').trim();
  if (!hex || hex.length < 32 || /[^a-fA-F0-9]/.test(hex)) return null;
  return Buffer.from(hex, 'hex');
}
const SIGNING_SECRET = getSecret();

// --------------------------------------------------------------- helpers ---
const rid = (n = 9) => crypto.randomBytes(n).toString('base64url');

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
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'bad_signature' };
  }
  return { ok: true, eventId, ticketId };
}

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

// ------------------------------------------------------------------ app ---
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // correct req.ip behind Vercel's proxy
app.use(express.json({ limit: '5mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(self)');
  next();
});

async function getSession(req) {
  const cookie = req.headers.cookie || '';
  const m = /(?:^|;\s*)gk_session=([^;]+)/.exec(cookie);
  if (!m) return null;
  const s = await store.getSession(m[1]).catch(() => null);
  if (!s) return null;
  const gen = await store.getSessGen().catch(() => 0);
  if (s.gen !== gen) return null; // invalidated by a restore
  return { token: m[1], ...s };
}
async function requireAuth(req, res, next) {
  try {
    const s = await getSession(req);
    if (!s) return res.status(401).json({ error: 'Host login required.' });
    req.session = s;
    next();
  } catch (e) {
    res.status(503).json({ error: 'Storage unavailable. Connect Vercel KV.' });
  }
}
function needSecret(req, res, next) {
  if (!SIGNING_SECRET) return res.status(503).json({ error: 'missing_secret', message: 'Set the GATEKEEPER_SECRET env var.' });
  next();
}
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie',
    `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}
const asyncWrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ------------------------------------------------------------- status ----
app.get('/api/status', asyncWrap(async (req, res) => {
  let storageOk = true;
  try { await store.ping(); } catch (e) { storageOk = false; }
  const host = storageOk ? await store.getHost().catch(() => null) : null;
  res.json({
    storageOk,
    missingSecret: !SIGNING_SECRET,
    setupNeeded: storageOk && !!SIGNING_SECRET && !host,
    loggedIn: storageOk && !!SIGNING_SECRET && !!(await getSession(req).catch(() => null)),
  });
}));

// ------------------------------------------------------------- auth API ---
app.post('/api/setup', needSecret, asyncWrap(async (req, res) => {
  if (await store.getHost()) return res.status(400).json({ error: 'Host account already exists. Log in instead.' });
  const pw = str(req.body && req.body.password, 128);
  if (!pw || pw.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  await store.setHost(hashPassword(pw));
  const token = rid(24);
  await store.createSession(token, await store.getSessGen());
  setSessionCookie(res, token);
  res.json({ ok: true });
}));

app.post('/api/login', needSecret, asyncWrap(async (req, res) => {
  const ip = req.ip || 'unknown';
  const host = await store.getHost();
  if (!host) return res.status(400).json({ error: 'No host account yet. Set one up first.' });
  if ((await store.rateLimitHit(ip)) === 'locked') {
    return res.status(429).json({ error: 'Too many failed attempts. Try again in 5 minutes.' });
  }
  const pw = str(req.body && req.body.password, 128, { allowEmpty: true }) || '';
  if (!checkPassword(pw, host)) {
    return res.status(401).json({ error: 'Wrong password.' });
  }
  await store.rateLimitClear(ip);
  const token = rid(24);
  await store.createSession(token, await store.getSessGen());
  setSessionCookie(res, token);
  res.json({ ok: true });
}));

app.post('/api/logout', asyncWrap(async (req, res) => {
  const s = await getSession(req).catch(() => null);
  if (s) await store.deleteSession(s.token).catch(() => {});
  clearSessionCookie(res);
  res.json({ ok: true });
}));

app.get('/api/me', requireAuth, (req, res) => res.json({ ok: true, role: 'host' }));

// ------------------------------------------------------------ events API ---
app.get('/api/events', needSecret, requireAuth, asyncWrap(async (req, res) => {
  res.json({ events: (await store.listEvents()).map(pubEvent) });
}));

app.post('/api/events', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const name = str(req.body && req.body.name, 120);
  if (!name) return res.status(400).json({ error: 'Event name is required.' });
  const e = {
    id: rid(8), name,
    date: str(req.body.date, 40, { allowEmpty: true }) || '',
    venue: str(req.body.venue, 160, { allowEmpty: true }) || '',
    notes: str(req.body.notes, 500, { allowEmpty: true }) || '',
    createdAt: new Date().toISOString()
  };
  await store.createEvent(e);
  res.json({ event: pubEvent(e) });
}));

app.delete('/api/events/:id', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const ev = await store.getEvent(String(req.params.id));
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  await store.deleteEvent(ev.id);
  res.json({ ok: true });
}));

// ------------------------------------------------------------ tickets API ---
app.get('/api/events/:id/tickets', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const ev = await store.getEvent(String(req.params.id));
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  res.json({ tickets: (await store.listTickets(ev.id)).map(pubTicket) });
}));

app.post('/api/events/:id/tickets', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const ev = await store.getEvent(String(req.params.id));
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  const count = intIn(req.body && req.body.count, 1, 500);
  const type = str(req.body && req.body.type, 60) || 'General';
  const holder = str(req.body && req.body.holder, 120, { allowEmpty: true }) || '';
  if (!count) return res.status(400).json({ error: 'Count must be between 1 and 500.' });
  const now = new Date().toISOString();
  const made = [];
  for (let i = 0; i < count; i++) {
    made.push({
      id: rid(9), eventId: ev.id, type,
      holder: count === 1 ? holder : '',
      usedAt: null, revoked: false, createdAt: now
    });
  }
  await store.createTickets(made);
  res.json({ tickets: made.map(pubTicket) });
}));

app.patch('/api/tickets/:id', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const t = await store.getTicket(String(req.params.id));
  if (!t) return res.status(404).json({ error: 'Ticket not found.' });
  const patch = {};
  if (typeof req.body.revoked === 'boolean') patch.revoked = req.body.revoked;
  const holder = str(req.body.holder, 120, { allowEmpty: true });
  if (holder !== null) patch.holder = holder;
  const updated = await store.updateTicket(t.id, patch);
  res.json({ ticket: pubTicket(updated) });
}));

app.delete('/api/tickets/:id', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const ok = await store.deleteTicket(String(req.params.id));
  if (!ok) return res.status(404).json({ error: 'Ticket not found.' });
  res.json({ ok: true });
}));

// ------------------------------------------------- verification (the gate) ---
app.post('/api/verify', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const now = new Date().toISOString();
  const log = (ticketId, status) =>
    store.logScan({ id: rid(6), ticketId: ticketId || null, status, at: now }).catch(() => {});

  const v = verifyCode(req.body && req.body.payload);
  if (!v.ok) {
    await log(null, 'invalid');
    return res.json({ status: 'invalid', reason: v.reason === 'bad_signature' ? 'forged_or_tampered' : 'not_a_ticket' });
  }
  const t = await store.getTicket(v.ticketId);
  if (!t || t.eventId !== v.eventId) { await log(null, 'invalid'); return res.json({ status: 'invalid', reason: 'unknown_ticket' }); }
  const ev = await store.getEvent(t.eventId);
  if (!ev) { await log(t.id, 'invalid'); return res.json({ status: 'invalid', reason: 'event_deleted' }); }
  if (t.revoked) { await log(t.id, 'revoked'); return res.json({ status: 'revoked', ticket: pubTicket(t), event: pubEvent(ev) }); }

  // Atomic claim: SET NX — only the first scan wins, even under concurrency.
  const won = await store.claimTicket(t.id, now);
  if (!won) {
    const usedAt = await store.getClaimedAt(t.id);
    await log(t.id, 'already_used');
    return res.json({ status: 'already_used', ticket: pubTicket({ ...t, usedAt: usedAt || t.usedAt }), event: pubEvent(ev) });
  }
  await log(t.id, 'valid');
  res.json({ status: 'valid', ticket: pubTicket({ ...t, usedAt: now }), event: pubEvent(ev) });
}));

app.get('/api/scans', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const limit = intIn(req.query.limit, 1, 100) || 20;
  res.json({ scans: await store.listScans(limit) });
}));

app.get('/api/stats', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const s = await store.getStats();
  const scans = await store.listScans(200);
  const today = new Date().toISOString().slice(0, 10);
  res.json({ ...s, scansToday: scans.filter(x => (x.at || '').slice(0, 10) === today).length });
}));

// ------------------------------------------------- backup & restore ---
app.get('/api/backup', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const events = await store.listEvents();
  const tickets = [];
  for (const ev of events) tickets.push(...await store.listTickets(ev.id));
  res.json({
    app: 'gatekeeper', version: 2, exportedAt: new Date().toISOString(),
    data: { host: await store.getHost(), events, tickets }
  });
}));

app.post('/api/restore', needSecret, requireAuth, asyncWrap(async (req, res) => {
  const d = req.body && req.body.data;
  if (!d || typeof d !== 'object') return res.status(400).json({ error: 'Invalid backup file.' });
  if (!d.host || typeof d.host !== 'object' || !Array.isArray(d.events) || !Array.isArray(d.tickets)) {
    return res.status(400).json({ error: 'Backup is missing host, events, or tickets.' });
  }
  if (d.events.length > 10000 || d.tickets.length > 50000) {
    return res.status(400).json({ error: 'Backup too large.' });
  }
  await store.restore(d);
  res.json({ ok: true, events: d.events.length, tickets: d.tickets.length });
}));

// ------------------------------------------------- error handler ---------
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('API error:', err && err.message);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

// ------------------------------------------- local dev only (not Vercel) ---
if (!IS_VERCEL) {
  app.use(express.static(path.join(__dirname, 'public')));
  app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
  app.listen(PORT, () => {
    console.log(`Gatekeeper running → http://localhost:${PORT}`);
  });
}

module.exports = app;
