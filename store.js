'use strict';
/* ============================================================================
 * Gatekeeper storage layer.
 *
 * Production (Vercel): @vercel/kv (Redis). Requires KV_REST_API_URL and
 * KV_REST_API_TOKEN — provisioned via Vercel Dashboard → Storage → KV.
 *
 * Local dev / tests: set GK_MEMORY_STORE=1 for an in-memory backend with the
 * same async interface (no network needed).
 *
 * Key layout (all prefixed gk:):
 *   gk:host                  host password record {salt,hash,algo}
 *   gk:sessgen               session generation (bumped on restore → logs everyone out)
 *   gk:session:<token>       {createdAt, gen}            TTL 24h
 *   gk:rl:<ip>               failed-login counter         TTL 5 min
 *   gk:event:<id>            event JSON
 *   gk:event_ids             set of event ids
 *   gk:ticket:<id>           ticket JSON {id,eventId,type,holder,revoked,createdAt,usedAt}
 *   gk:event_tickets:<eid>   set of ticket ids
 *   gk:claimed:<tid>         ISO timestamp of first scan (SET NX — the atomic gate)
 *   gk:scanlog               list of recent scan entries (capped at 200)
 *   gk:stat:tickets          total live tickets
 *   gk:stat:checkedin        total checked-in tickets
 * ========================================================================== */

const SESSION_TTL_SEC = 24 * 60 * 60;
const RATELIMIT_TTL_SEC = 5 * 60;
const SCANLOG_MAX = 200;

const memoryMode = process.env.GK_MEMORY_STORE === '1';

function notConfigured() {
  return new Error('storage_not_configured: provision Vercel KV and connect it to this project (Dashboard → Storage → KV).');
}

/* ---------------------------------------------------------- KV backend --- */
function kvBackend() {
  if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) throw notConfigured();
  const { kv } = require('@vercel/kv');
  const J = {
    async ping() { await kv.ping(); },
    // -- host --
    getHost: () => kv.get('gk:host'),
    setHost: (rec) => kv.set('gk:host', rec),
    // -- sessions --
    async getSessGen() { return (await kv.get('gk:sessgen')) || 0; },
    async bumpSessGen() { return kv.incr('gk:sessgen'); },
    createSession: (token, gen) => kv.set(`gk:session:${token}`, { createdAt: Date.now(), gen }, { ex: SESSION_TTL_SEC }),
    getSession: (token) => kv.get(`gk:session:${token}`),
    deleteSession: (token) => kv.del(`gk:session:${token}`),
    // -- login rate limiting --
    async rateLimitHit(ip) {
      const n = await kv.incr(`gk:rl:${ip}`);
      if (n === 1) await kv.expire(`gk:rl:${ip}`, RATELIMIT_TTL_SEC);
      return n > 5 ? 'locked' : 'ok';
    },
    rateLimitClear: (ip) => kv.del(`gk:rl:${ip}`),
    // -- events --
    async listEvents() {
      const ids = await kv.smembers('gk:event_ids');
      if (!ids.length) return [];
      const evs = await Promise.all(ids.map(id => kv.get(`gk:event:${id}`)));
      return evs.filter(Boolean).sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    },
    getEvent: (id) => kv.get(`gk:event:${id}`),
    async createEvent(ev) {
      await kv.set(`gk:event:${ev.id}`, ev);
      await kv.sadd('gk:event_ids', ev.id);
    },
    async deleteEvent(id) {
      const tids = await kv.smembers(`gk:event_tickets:${id}`);
      let usedCount = 0;
      await Promise.all(tids.map(async tid => {
        const claimed = await kv.get(`gk:claimed:${tid}`);
        if (claimed) usedCount++;
        await kv.del(`gk:ticket:${tid}`);
        await kv.del(`gk:claimed:${tid}`);
      }));
      await kv.del(`gk:event_tickets:${id}`);
      await kv.del(`gk:event:${id}`);
      await kv.srem('gk:event_ids', id);
      if (tids.length) await kv.incrby('gk:stat:tickets', -tids.length);
      if (usedCount) await kv.incrby('gk:stat:checkedin', -usedCount);
    },
    // -- tickets --
    async listTickets(eventId) {
      const ids = await kv.smembers(`gk:event_tickets:${eventId}`);
      if (!ids.length) return [];
      const ts = await Promise.all(ids.map(tid => kv.get(`gk:ticket:${tid}`)));
      return ts.filter(Boolean).sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
    },
    getTicket: (id) => kv.get(`gk:ticket:${id}`),
    async createTickets(tickets) {
      await Promise.all(tickets.map(async t => {
        await kv.set(`gk:ticket:${t.id}`, t);
        await kv.sadd(`gk:event_tickets:${t.eventId}`, t.id);
      }));
      if (tickets.length) await kv.incrby('gk:stat:tickets', tickets.length);
    },
    async updateTicket(id, patch) {
      const t = await kv.get(`gk:ticket:${id}`);
      if (!t) return null;
      Object.assign(t, patch);
      await kv.set(`gk:ticket:${id}`, t);
      return t;
    },
    async deleteTicket(id) {
      const t = await kv.get(`gk:ticket:${id}`);
      if (!t) return false;
      await kv.del(`gk:ticket:${id}`);
      await kv.srem(`gk:event_tickets:${t.eventId}`, id);
      await kv.incrby('gk:stat:tickets', -1);
      const claimed = await kv.get(`gk:claimed:${id}`);
      await kv.del(`gk:claimed:${id}`);
      if (claimed) await kv.incrby('gk:stat:checkedin', -1);
      return true;
    },
    // -- atomic check-in: SET NX is the gate; only one scan can win --
    async claimTicket(id, usedAt) {
      const won = await kv.set(`gk:claimed:${id}`, usedAt, { nx: true });
      if (!won) return false;
      const t = await kv.get(`gk:ticket:${id}`);
      if (t) { t.usedAt = usedAt; await kv.set(`gk:ticket:${id}`, t); }
      await kv.incr('gk:stat:checkedin');
      return true;
    },
    getClaimedAt: (id) => kv.get(`gk:claimed:${id}`),
    // -- scan log --
    async logScan(entry) {
      await kv.lpush('gk:scanlog', entry);
      await kv.ltrim('gk:scanlog', 0, SCANLOG_MAX - 1);
    },
    listScans: (limit) => kv.lrange('gk:scanlog', 0, limit - 1),
    // -- stats --
    async getStats() {
      const [events, tickets, checkedIn] = await Promise.all([
        kv.scard('gk:event_ids'),
        kv.get('gk:stat:tickets'),
        kv.get('gk:stat:checkedin'),
      ]);
      return { events, tickets: tickets || 0, checkedIn: checkedIn || 0 };
    },
    // -- full restore (backup import) --
    async restore(data) {
      const ids = await kv.smembers('gk:event_ids');
      for (const id of ids) await J.deleteEvent(id);
      await kv.del('gk:scanlog');
      await kv.set('gk:host', data.host);
      await kv.set('gk:stat:tickets', 0);
      await kv.set('gk:stat:checkedin', 0);
      for (const ev of data.events) await J.createEvent(ev);
      let checkedIn = 0;
      for (const t of data.tickets) {
        await kv.set(`gk:ticket:${t.id}`, t);
        await kv.sadd(`gk:event_tickets:${t.eventId}`, t.id);
        if (t.usedAt) { await kv.set(`gk:claimed:${t.id}`, t.usedAt); checkedIn++; }
      }
      if (data.tickets.length) await kv.incrby('gk:stat:tickets', data.tickets.length);
      if (checkedIn) await kv.incrby('gk:stat:checkedin', checkedIn);
      await J.bumpSessGen(); // invalidate all existing sessions
    },
  };
  return J;
}

/* ------------------------------------------------------ memory backend --- */
/* Same interface, for local dev/tests (GK_MEMORY_STORE=1). Single-process, so
   read-modify-write is naturally atomic here. */
function memoryBackend() {
  const kv = new Map();       // key -> value
  const ttl = new Map();      // key -> expiresAt ms
  const sets = new Map();     // key -> Set
  const lists = new Map();    // key -> Array
  const get = (k) => {
    const exp = ttl.get(k);
    if (exp && exp < Date.now()) { kv.delete(k); ttl.delete(k); return undefined; }
    return kv.get(k);
  };
  const J = {
    async ping() {},
    getHost: async () => get('gk:host') || null,
    setHost: async (rec) => { kv.set('gk:host', rec); },
    getSessGen: async () => get('gk:sessgen') || 0,
    bumpSessGen: async () => { const n = (get('gk:sessgen') || 0) + 1; kv.set('gk:sessgen', n); return n; },
    createSession: async (token, gen) => { kv.set(`gk:session:${token}`, { createdAt: Date.now(), gen }); ttl.set(`gk:session:${token}`, Date.now() + SESSION_TTL_SEC * 1000); },
    getSession: async (token) => get(`gk:session:${token}`) || null,
    deleteSession: async (token) => { kv.delete(`gk:session:${token}`); ttl.delete(`gk:session:${token}`); },
    rateLimitHit: async (ip) => {
      const k = `gk:rl:${ip}`;
      const n = (get(k) || 0) + 1;
      kv.set(k, n); ttl.set(k, Date.now() + RATELIMIT_TTL_SEC * 1000);
      return n > 5 ? 'locked' : 'ok';
    },
    rateLimitClear: async (ip) => { kv.delete(`gk:rl:${ip}`); ttl.delete(`gk:rl:${ip}`); },
    listEvents: async () => {
      const ids = [...(sets.get('gk:event_ids') || [])];
      return ids.map(id => get(`gk:event:${id}`)).filter(Boolean)
        .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    },
    getEvent: async (id) => get(`gk:event:${id}`) || null,
    createEvent: async (ev) => {
      kv.set(`gk:event:${ev.id}`, { ...ev });
      if (!sets.has('gk:event_ids')) sets.set('gk:event_ids', new Set());
      sets.get('gk:event_ids').add(ev.id);
    },
    deleteEvent: async (id) => {
      const tids = [...(sets.get(`gk:event_tickets:${id}`) || [])];
      let usedCount = 0;
      for (const tid of tids) {
        if (get(`gk:claimed:${tid}`)) usedCount++;
        kv.delete(`gk:ticket:${tid}`); kv.delete(`gk:claimed:${tid}`);
      }
      sets.delete(`gk:event_tickets:${id}`);
      kv.delete(`gk:event:${id}`);
      (sets.get('gk:event_ids') || new Set()).delete(id);
      kv.set('gk:stat:tickets', Math.max(0, (get('gk:stat:tickets') || 0) - tids.length));
      kv.set('gk:stat:checkedin', Math.max(0, (get('gk:stat:checkedin') || 0) - usedCount));
    },
    listTickets: async (eventId) => {
      const ids = [...(sets.get(`gk:event_tickets:${eventId}`) || [])];
      return ids.map(tid => get(`gk:ticket:${tid}`)).filter(Boolean)
        .sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
    },
    getTicket: async (id) => get(`gk:ticket:${id}`) || null,
    createTickets: async (tickets) => {
      for (const t of tickets) {
        kv.set(`gk:ticket:${t.id}`, { ...t });
        if (!sets.has(`gk:event_tickets:${t.eventId}`)) sets.set(`gk:event_tickets:${t.eventId}`, new Set());
        sets.get(`gk:event_tickets:${t.eventId}`).add(t.id);
      }
      kv.set('gk:stat:tickets', (get('gk:stat:tickets') || 0) + tickets.length);
    },
    updateTicket: async (id, patch) => {
      const t = get(`gk:ticket:${id}`);
      if (!t) return null;
      Object.assign(t, patch);
      kv.set(`gk:ticket:${id}`, t);
      return t;
    },
    deleteTicket: async (id) => {
      const t = get(`gk:ticket:${id}`);
      if (!t) return false;
      const claimed = get(`gk:claimed:${id}`);
      kv.delete(`gk:ticket:${id}`); kv.delete(`gk:claimed:${id}`);
      (sets.get(`gk:event_tickets:${t.eventId}`) || new Set()).delete(id);
      kv.set('gk:stat:tickets', Math.max(0, (get('gk:stat:tickets') || 0) - 1));
      if (claimed) kv.set('gk:stat:checkedin', Math.max(0, (get('gk:stat:checkedin') || 0) - 1));
      return true;
    },
    claimTicket: async (id, usedAt) => {
      if (get(`gk:claimed:${id}`)) return false;
      kv.set(`gk:claimed:${id}`, usedAt);
      const t = get(`gk:ticket:${id}`);
      if (t) { t.usedAt = usedAt; kv.set(`gk:ticket:${id}`, t); }
      kv.set('gk:stat:checkedin', (get('gk:stat:checkedin') || 0) + 1);
      return true;
    },
    getClaimedAt: async (id) => get(`gk:claimed:${id}`) || null,
    logScan: async (entry) => {
      if (!lists.has('gk:scanlog')) lists.set('gk:scanlog', []);
      const l = lists.get('gk:scanlog');
      l.unshift(entry);
      lists.set('gk:scanlog', l.slice(0, SCANLOG_MAX));
    },
    listScans: async (limit) => (lists.get('gk:scanlog') || []).slice(0, limit),
    getStats: async () => ({
      events: (sets.get('gk:event_ids') || new Set()).size,
      tickets: get('gk:stat:tickets') || 0,
      checkedIn: get('gk:stat:checkedin') || 0,
    }),
    restore: async (data) => {
      const ids = [...(sets.get('gk:event_ids') || [])];
      for (const id of ids) await J.deleteEvent(id);
      lists.set('gk:scanlog', []);
      kv.set('gk:host', data.host);
      kv.set('gk:stat:tickets', 0);
      kv.set('gk:stat:checkedin', 0);
      for (const ev of data.events) await J.createEvent(ev);
      let checkedIn = 0;
      for (const t of data.tickets) {
        kv.set(`gk:ticket:${t.id}`, { ...t });
        if (!sets.has(`gk:event_tickets:${t.eventId}`)) sets.set(`gk:event_tickets:${t.eventId}`, new Set());
        sets.get(`gk:event_tickets:${t.eventId}`).add(t.id);
        if (t.usedAt) { kv.set(`gk:claimed:${t.id}`, t.usedAt); checkedIn++; }
      }
      kv.set('gk:stat:tickets', data.tickets.length);
      kv.set('gk:stat:checkedin', checkedIn);
      await J.bumpSessGen();
    },
  };
  return J;
}

module.exports = memoryMode ? memoryBackend() : kvBackend();
module.exports.SESSION_TTL_SEC = SESSION_TTL_SEC;
