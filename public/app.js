/* Gatekeeper frontend — host-only single-page app */
'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON */ }
  if (!res.ok) throw new Error((data && data.error) || ('Request failed (' + res.status + ')'));
  return data;
}

function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  $('#toast-root').appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

function openModal(html) {
  const root = $('#modal-root');
  root.innerHTML = '<div class="modal-backdrop"><div class="modal">' + html + '</div></div>';
  root.querySelector('.modal-backdrop').addEventListener('click', e => {
    if (e.target.classList.contains('modal-backdrop')) closeModal();
  });
}
function closeModal() { $('#modal-root').innerHTML = ''; }

/* ---------------- custom QR rendering ---------------- */
const LOGO_SVG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
  '<circle cx="32" cy="32" r="30" fill="#0d0d10"/>' +
  '<circle cx="32" cy="32" r="29" fill="none" stroke="#e8b84b" stroke-width="2"/>' +
  '<text x="32" y="43" font-family="Georgia,serif" font-size="30" fill="#e8b84b" text-anchor="middle">G</text></svg>'
);

function makeQR(code, size) {
  return new QRCodeStyling({
    width: size, height: size, type: 'canvas', data: code,
    image: LOGO_SVG,
    dotsOptions: { color: '#101014', type: 'rounded' },
    cornersSquareOptions: { color: '#8a6a25', type: 'extra-rounded' },
    cornersDotOptions: { color: '#8a6a25', type: 'dot' },
    backgroundOptions: { color: '#ffffff' },
    imageOptions: { crossOrigin: 'anonymous', margin: 6, imageSize: 0.38 }
  });
}
function renderQRInto(el, code, size) {
  el.innerHTML = '';
  makeQR(code, size).append(el);
}

/* ---------------- state ---------------- */
const S = {
  loggedIn: false,
  setupNeeded: false,
  events: [],
  currentEvent: null,
  tickets: [],
  selected: new Set(),
  scanner: null,
  lastScan: { code: '', at: 0 },
  printTickets: []
};

/* ---------------- boot & router ---------------- */
async function boot() {
  let st;
  try {
    st = await api('GET', '/api/status');
  } catch (e) {
    $('#view').innerHTML = '<div class="empty"><div class="big">⚠️</div><p>Could not reach the Gatekeeper server.<br>Is it running? <code>npm start</code></p></div>';
    return;
  }
  S.storageOk = st.storageOk !== false;
  S.missingSecret = !!st.missingSecret;
  S.setupNeeded = !!st.setupNeeded;
  S.loggedIn = !!st.loggedIn;
  $('#logout-btn').addEventListener('click', async () => {
    stopScanner();
    await api('POST', '/api/logout').catch(() => {});
    S.loggedIn = false;
    location.hash = '#/login';
    router();
  });
  window.addEventListener('hashchange', router);
  router();
}

function setNav(active) {
  $('#topbar').classList.toggle('hidden', !S.loggedIn);
  $$('#topbar nav a').forEach(a => a.classList.toggle('active', a.dataset.nav === active));
}

function router() {
  stopScanner();
  closeModal();
  const h = location.hash || '#/';
  if (!S.storageOk) { setNav(''); return showStorageHelp(); }
  if (S.missingSecret) { setNav(''); return showSecretSetup(); }
  if (S.setupNeeded) { setNav(''); return showSetup(); }
  if (!S.loggedIn && h !== '#/login') { location.hash = '#/login'; return; }

  let m;
  if (h === '#/' || h === '') { setNav('events'); return showDashboard(); }
  if (h === '#/login') { setNav(''); return showLogin(); }
  if (h === '#/scan') { setNav('scan'); return showScan(); }
  if ((m = /^#\/event\/([A-Za-z0-9_-]+)$/.exec(h))) { setNav('events'); return showEvent(m[1]); }
  if ((m = /^#\/event\/([A-Za-z0-9_-]+)\/print$/.exec(h))) { setNav('events'); return showPrint(m[1]); }
  location.hash = '#/';
}

/* ---------------- first-run: storage & secret ---------------- */
function showStorageHelp() {
  $('#view').innerHTML = `
    <div class="auth-wrap"><div class="card auth-card">
      <div class="brand-mark">G</div>
      <h1>Connect storage</h1>
      <p>Gatekeeper needs a database before it can issue tickets. This takes about a minute:</p>
      <div class="security-note" style="text-align:left">
        <b>1.</b> In your Vercel dashboard, open this project → <b>Storage</b> tab.<br>
        <b>2.</b> Click <b>Create Database</b> → choose <b>KV</b> → <b>Continue</b>.<br>
        <b>3.</b> Connect it to this project when asked.<br>
        <b>4.</b> Come back here and refresh — setup continues automatically.
      </div>
      <button class="btn btn-block" style="margin-top:18px" onclick="location.reload()">Refresh</button>
    </div></div>`;
}

function showSecretSetup() {
  $('#view').innerHTML = `
    <div class="auth-wrap"><div class="card auth-card">
      <div class="brand-mark">G</div>
      <h1>Set the signing secret</h1>
      <p>Every ticket QR is sealed with a secret key. Generate one, add it as an environment variable, then redeploy:</p>
      <div class="field"><label>Your secret (64 hex characters)</label>
        <input id="secret-val" readonly placeholder="Press Generate…">
      </div>
      <div class="btn-row">
        <button class="btn btn-ghost btn-sm" id="secret-gen" style="flex:1">Generate</button>
        <button class="btn btn-ghost btn-sm" id="secret-copy" style="flex:1">Copy</button>
      </div>
      <div class="security-note" style="text-align:left;margin-top:16px">
        <b>1.</b> Press <b>Generate</b>, then <b>Copy</b>.<br>
        <b>2.</b> Vercel dashboard → this project → <b>Settings</b> → <b>Environment Variables</b>.<br>
        <b>3.</b> Add variable named <b><code>GATEKEEPER_SECRET</code></b>, paste the value, save.<br>
        <b>4.</b> <b>Deployments</b> tab → <b>Redeploy</b>. Then refresh this page.<br><br>
        <b>Keep this secret safe.</b> Losing it invalidates every pass ever issued.
      </div>
    </div></div>`;
  $('#secret-gen').addEventListener('click', () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    $('#secret-val').value = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  });
  $('#secret-copy').addEventListener('click', async () => {
    const v = $('#secret-val').value;
    if (!v) return toast('Generate a secret first.', 'err');
    try { await navigator.clipboard.writeText(v); toast('Copied.', 'ok'); }
    catch (e) { $('#secret-val').select(); toast('Copy it manually.', 'err'); }
  });
}

/* ---------------- auth views ---------------- */
function showSetup() {
  $('#view').innerHTML = `
    <div class="auth-wrap"><div class="card auth-card">
      <div class="brand-mark">G</div>
      <h1>Create your host password</h1>
      <p>This password is the <b>only</b> key to Gatekeeper. Whoever has it can create tickets and scan people in — keep it private.</p>
      <form id="setup-form">
        <div class="field"><label>Host password</label>
          <input type="password" id="pw1" minlength="8" required autocomplete="new-password" placeholder="At least 8 characters"></div>
        <div class="field"><label>Confirm password</label>
          <input type="password" id="pw2" minlength="8" required autocomplete="new-password" placeholder="Repeat it"></div>
        <button class="btn btn-block" type="submit">Create host account</button>
      </form>
      <div class="security-note"><b>How your tickets stay unforgeable:</b> every QR is sealed with a server-only cryptographic signature. Only this app can create or verify tickets — a copied or hand-edited QR will fail the check at the gate.</div>
    </div></div>`;
  $('#setup-form').addEventListener('submit', async e => {
    e.preventDefault();
    const a = $('#pw1').value, b = $('#pw2').value;
    if (a !== b) return toast('Passwords do not match.', 'err');
    try {
      await api('POST', '/api/setup', { password: a });
      S.setupNeeded = false; S.loggedIn = true;
      toast('Host account created. Welcome in.', 'ok');
      location.hash = '#/'; router();
    } catch (err) { toast(err.message, 'err'); }
  });
}

function showLogin() {
  $('#view').innerHTML = `
    <div class="auth-wrap"><div class="card auth-card">
      <div class="brand-mark">G</div>
      <h1>Host login</h1>
      <p>Only the host can create passes and scan them in.</p>
      <form id="login-form">
        <div class="field"><label>Host password</label>
          <input type="password" id="pw" required autocomplete="current-password" placeholder="Your host password"></div>
        <button class="btn btn-block" type="submit">Log in</button>
      </form>
    </div></div>`;
  $('#login-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      await api('POST', '/api/login', { password: $('#pw').value });
      S.loggedIn = true;
      toast('Logged in.', 'ok');
      location.hash = '#/'; router();
    } catch (err) { toast(err.message, 'err'); }
  });
  $('#pw').focus();
}

/* ---------------- dashboard ---------------- */
async function showDashboard() {
  $('#view').innerHTML = '<div class="empty"><p>Loading…</p></div>';
  try {
    const [ev, stats] = await Promise.all([api('GET', '/api/events'), api('GET', '/api/stats')]);
    S.events = ev.events;
  } catch (e) { return $('#view').innerHTML = '<div class="empty"><p>' + esc(e.message) + '</p></div>'; }

  const st = await api('GET', '/api/stats').catch(() => ({ events: 0, tickets: 0, checkedIn: 0 }));
  const cards = S.events.map(e => `
    <a class="card event-card" href="#/event/${esc(e.id)}">
      <div class="event-date">${esc(eventDateShort(e.date))}</div>
      <div class="event-info">
        <h2>${esc(e.name)}</h2>
        <div class="meta">${esc(e.venue || 'No venue set')}</div>
      </div>
      <div class="event-stats">
        <div><div class="n" id="ev-t-${esc(e.id)}">–</div><div class="l">passes</div></div>
        <div><div class="n" id="ev-u-${esc(e.id)}">–</div><div class="l">in</div></div>
      </div>
    </a>`).join('');

  $('#view').innerHTML = `
    <div class="page-head">
      <div><h1>Events</h1><p>Create an event, generate its passes, and scan them at the gate. Every QR is cryptographically sealed to its event.</p></div>
      <button class="btn" id="new-event-btn">+ New event</button>
    </div>
    <div class="grid cols-4" style="margin-bottom:20px">
      <div class="card"><h3>Events</h3><div class="stat-num">${st.events}</div></div>
      <div class="card"><h3>Passes issued</h3><div class="stat-num gold">${st.tickets}</div></div>
      <div class="card"><h3>Checked in</h3><div class="stat-num green">${st.checkedIn}</div></div>
      <div class="card"><h3>Scans today</h3><div class="stat-num">${st.scansToday || 0}</div></div>
    </div>
    <div class="card" style="margin-bottom:20px">
      <h3>Backup</h3>
      <p style="color:var(--muted);font-size:13px;margin:0 0 12px;line-height:1.6">Download a copy of all events and passes before redeploying or moving hosts — then restore it in one click.</p>
      <div class="btn-row">
        <button class="btn btn-ghost btn-sm" id="backup-btn">⬇ Download backup</button>
        <label class="btn btn-ghost btn-sm" style="cursor:pointer">⬆ Restore backup<input type="file" id="restore-file" accept="application/json" class="hidden"></label>
      </div>
    </div>
    <div class="grid">${cards || '<div class="card empty"><div class="big">🎟️</div><p>No events yet. Create your first one to start issuing passes.</p></div>'}</div>`;

  $('#new-event-btn').addEventListener('click', showNewEventModal);

  $('#backup-btn').addEventListener('click', async () => {
    try {
      const d = await api('GET', '/api/backup');
      const blob = new Blob([JSON.stringify(d)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'gatekeeper-backup-' + new Date().toISOString().slice(0, 10) + '.json';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      toast('Backup downloaded.', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#restore-file').addEventListener('change', async e => {
    const f = e.target.files[0]; e.target.value = '';
    if (!f) return;
    if (!confirm('Restore this backup? It REPLACES all current events and passes, and logs everyone out.')) return;
    try {
      const parsed = JSON.parse(await f.text());
      const r = await api('POST', '/api/restore', { data: parsed.data });
      toast('Restored ' + r.events + ' event(s), ' + r.tickets + ' pass(es). Please log in again.', 'ok');
      S.loggedIn = false; location.hash = '#/login'; router();
    } catch (err) { toast('Restore failed: ' + err.message, 'err'); }
  });
  // fill per-event counts
  for (const e of S.events) {
    api('GET', '/api/events/' + encodeURIComponent(e.id) + '/tickets').then(d => {
      const el1 = $('#ev-t-' + CSS.escape(e.id)), el2 = $('#ev-u-' + CSS.escape(e.id));
      if (el1) el1.textContent = d.tickets.length;
      if (el2) el2.textContent = d.tickets.filter(t => t.usedAt).length;
    }).catch(() => {});
  }
}

function eventDateShort(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (isNaN(d)) return esc(dateStr).slice(0, 10);
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}

function showNewEventModal() {
  openModal(`
    <h2>New event</h2><div class="sub">Passes are sealed to this event and can't be reused elsewhere.</div>
    <form id="new-event-form" style="text-align:left">
      <div class="field"><label>Event name</label><input id="ne-name" required maxlength="120" placeholder="e.g. Neon Rooftop Night"></div>
      <div class="form-row">
        <div class="field"><label>Date</label><input id="ne-date" type="date"></div>
        <div class="field"><label>Venue</label><input id="ne-venue" maxlength="160" placeholder="e.g. Skyline Terrace"></div>
      </div>
      <div class="field"><label>Notes (optional)</label><input id="ne-notes" maxlength="500" placeholder="Door policy, timings…"></div>
      <div class="btn-row"><button class="btn" type="submit" style="flex:1">Create event</button>
      <button class="btn btn-ghost" type="button" id="ne-cancel">Cancel</button></div>
    </form>`);
  $('#ne-cancel').addEventListener('click', closeModal);
  $('#new-event-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      await api('POST', '/api/events', {
        name: $('#ne-name').value, date: $('#ne-date').value,
        venue: $('#ne-venue').value, notes: $('#ne-notes').value
      });
      closeModal(); toast('Event created.', 'ok'); showDashboard();
    } catch (err) { toast(err.message, 'err'); }
  });
}

/* ---------------- event detail ---------------- */
async function showEvent(id) {
  $('#view').innerHTML = '<div class="empty"><p>Loading…</p></div>';
  let ev;
  try {
    const d = await api('GET', '/api/events');
    ev = d.events.find(x => x.id === id);
    if (!ev) throw new Error('Event not found.');
    const t = await api('GET', '/api/events/' + encodeURIComponent(id) + '/tickets');
    S.currentEvent = ev; S.tickets = t.tickets; S.selected = new Set();
  } catch (e) {
    $('#view').innerHTML = '<div class="empty"><p>' + esc(e.message) + '</p><a href="#/">← Back to events</a></div>';
    return;
  }
  renderEventPage();
}

function ticketStatus(t) {
  if (t.revoked) return '<span class="pill revoked">Revoked</span>';
  if (t.usedAt) return '<span class="pill used">Checked in</span>';
  return '<span class="pill active">Active</span>';
}

function renderEventPage() {
  const ev = S.currentEvent;
  const used = S.tickets.filter(t => t.usedAt).length;
  const active = S.tickets.filter(t => !t.usedAt && !t.revoked).length;

  const rows = S.tickets.map(t => `
    <tr>
      <td><input type="checkbox" data-sel="${esc(t.id)}" ${S.selected.has(t.id) ? 'checked' : ''}></td>
      <td><span class="type-tag">${esc(t.type)}</span></td>
      <td>${esc(t.holder || '—')}</td>
      <td style="font-family:ui-monospace,monospace;font-size:12px">${esc(t.id)}</td>
      <td>${ticketStatus(t)}</td>
      <td><div class="row-actions">
        <button class="link-btn" data-qr="${esc(t.id)}">QR</button>
        <button class="link-btn" data-name="${esc(t.id)}">Name</button>
        <button class="link-btn ${t.revoked ? '' : 'danger'}" data-revoke="${esc(t.id)}">${t.revoked ? 'Restore' : 'Revoke'}</button>
        <button class="link-btn danger" data-del="${esc(t.id)}">Delete</button>
      </div></td>
    </tr>`).join('');

  $('#view').innerHTML = `
    <div class="page-head">
      <div>
        <a href="#/" style="font-size:13px">← All events</a>
        <h1 style="margin-top:6px">${esc(ev.name)}</h1>
        <p>${esc([ev.date, ev.venue].filter(Boolean).join(' · ') || 'No date / venue set')}${ev.notes ? ' — ' + esc(ev.notes) : ''}</p>
      </div>
      <div class="btn-row">
        <a class="btn btn-ghost" href="#/scan">Open scanner</a>
        <button class="btn btn-danger" id="del-event-btn">Delete event</button>
      </div>
    </div>
    <div class="grid cols-3" style="margin-bottom:6px">
      <div class="card"><h3>Passes</h3><div class="stat-num gold">${S.tickets.length}</div></div>
      <div class="card"><h3>Checked in</h3><div class="stat-num green">${used}</div></div>
      <div class="card"><h3>Active</h3><div class="stat-num">${active}</div></div>
    </div>

    <div class="card" style="margin-top:16px">
      <h3 style="margin-bottom:12px">Issue new passes</h3>
      <form id="issue-form">
        <div class="form-row">
          <div class="field"><label>Quantity (1–500)</label><input id="is-count" type="number" min="1" max="500" value="1" required></div>
          <div class="field"><label>Pass type</label><input id="is-type" maxlength="60" value="General" required placeholder="General, VIP, Crew…"></div>
        </div>
        <div class="field"><label>Holder name <span style="font-weight:400">(only used when issuing a single pass)</span></label>
          <input id="is-holder" maxlength="120" placeholder="e.g. Aarav Sharma"></div>
        <button class="btn" type="submit">Generate passes</button>
        <div class="hint" style="margin-top:8px">Each pass gets a unique, signed QR. Forged or edited codes fail verification at the gate.</div>
      </form>
    </div>

    <div class="toolbar">
      <strong>${S.tickets.length} passes</strong>
      <span class="spacer"></span>
      <button class="btn btn-ghost btn-sm" id="sel-all">Select all</button>
      <button class="btn btn-ghost btn-sm" id="print-sel">🖨 Print selected</button>
      <button class="btn btn-ghost btn-sm" id="print-all">🖨 Print all</button>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th></th><th>Type</th><th>Holder</th><th>Pass ID</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:30px">No passes yet — issue some above.</td></tr>'}</tbody>
    </table></div>`;

  $('#del-event-btn').addEventListener('click', async () => {
    if (!confirm('Delete this event and ALL its passes? This cannot be undone.')) return;
    try { await api('DELETE', '/api/events/' + encodeURIComponent(ev.id)); toast('Event deleted.', 'ok'); location.hash = '#/'; }
    catch (e) { toast(e.message, 'err'); }
  });

  $('#issue-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      const d = await api('POST', '/api/events/' + encodeURIComponent(ev.id) + '/tickets', {
        count: $('#is-count').value, type: $('#is-type').value, holder: $('#is-holder').value
      });
      S.tickets = [...d.tickets, ...S.tickets];
      toast(d.tickets.length + ' pass(es) generated.', 'ok');
      renderEventPage();
      if (d.tickets.length === 1) showQRModal(d.tickets[0]);
    } catch (err) { toast(err.message, 'err'); }
  });

  $('#sel-all').addEventListener('click', () => {
    if (S.selected.size === S.tickets.length) S.selected.clear();
    else S.tickets.forEach(t => S.selected.add(t.id));
    renderEventPage();
  });
  $('#print-sel').addEventListener('click', () => {
    const list = S.tickets.filter(t => S.selected.has(t.id));
    if (!list.length) return toast('Select at least one pass first.', 'err');
    S.printTickets = list; doPrint(ev);
  });
  $('#print-all').addEventListener('click', () => {
    if (!S.tickets.length) return toast('No passes to print.', 'err');
    S.printTickets = [...S.tickets]; doPrint(ev);
  });

  $$('#view [data-sel]').forEach(cb => cb.addEventListener('change', () => {
    cb.checked ? S.selected.add(cb.dataset.sel) : S.selected.delete(cb.dataset.sel);
  }));
  $$('#view [data-qr]').forEach(b => b.addEventListener('click', () => {
    showQRModal(S.tickets.find(t => t.id === b.dataset.qr));
  }));
  $$('#view [data-name]').forEach(b => b.addEventListener('click', async () => {
    const t = S.tickets.find(x => x.id === b.dataset.name);
    const name = prompt('Holder name for this pass:', t.holder || '');
    if (name === null) return;
    try {
      const d = await api('PATCH', '/api/tickets/' + encodeURIComponent(t.id), { holder: name });
      Object.assign(t, d.ticket); renderEventPage(); toast('Updated.', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  }));
  $$('#view [data-revoke]').forEach(b => b.addEventListener('click', async () => {
    const t = S.tickets.find(x => x.id === b.dataset.revoke);
    try {
      const d = await api('PATCH', '/api/tickets/' + encodeURIComponent(t.id), { revoked: !t.revoked });
      Object.assign(t, d.ticket); renderEventPage();
      toast(t.revoked ? 'Pass revoked — it will now fail at the gate.' : 'Pass restored.', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  }));
  $$('#view [data-del]').forEach(b => b.addEventListener('click', async () => {
    if (!confirm('Delete this pass permanently?')) return;
    try {
      await api('DELETE', '/api/tickets/' + encodeURIComponent(b.dataset.del));
      S.tickets = S.tickets.filter(t => t.id !== b.dataset.del);
      S.selected.delete(b.dataset.del); renderEventPage(); toast('Pass deleted.', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  }));
}

function showQRModal(t) {
  if (!t) return;
  openModal(`
    <h2>${esc(t.type)} pass</h2>
    <div class="sub">${esc(S.currentEvent ? S.currentEvent.name : '')}${t.holder ? ' · ' + esc(t.holder) : ''}</div>
    <div class="qr-frame" id="qr-modal-frame"></div>
    <div class="ticket-id">${esc(t.id)}</div>
    <div class="btn-row" style="justify-content:center">
      <button class="btn btn-sm" id="qr-download">Download PNG</button>
      <button class="btn btn-ghost btn-sm" id="qr-close">Close</button>
    </div>`);
  renderQRInto($('#qr-modal-frame'), t.code, 240);
  $('#qr-close').addEventListener('click', closeModal);
  $('#qr-download').addEventListener('click', () => {
    makeQR(t.code, 600).download({ name: 'gatekeeper-' + t.id, extension: 'png' });
  });
}

/* ---------------- printing ---------------- */
function doPrint(ev) {
  document.querySelectorAll('.print-sheet').forEach(el => el.remove());
  const sheet = document.createElement('div');
  sheet.className = 'print-sheet';
  sheet.innerHTML = `
    <div class="print-header"><h1>${esc(ev.name)}</h1>
    <p>${esc([ev.date, ev.venue].filter(Boolean).join(' · '))} — ${S.printTickets.length} pass(es)</p></div>
    <div class="print-grid">
      ${S.printTickets.map(t => `
        <div class="ticket-card">
          <div class="qr" data-code="${esc(t.code)}"></div>
          <div>
            <h3>${esc(ev.name)}</h3>
            <span class="t-type">${esc(t.type)}</span>
            <div class="t-meta">${t.holder ? esc(t.holder) + '<br>' : ''}${esc([ev.date, ev.venue].filter(Boolean).join(' · '))}</div>
            <div class="t-code">${esc(t.id)}</div>
          </div>
        </div>`).join('')}
    </div>`;
  document.body.appendChild(sheet);
  $$('.print-sheet [data-code]').forEach(el => renderQRInto(el, el.dataset.code, 130));
  setTimeout(() => window.print(), 400);
}

/* ---------------- scanner ---------------- */
function stopScanner() {
  if (S.scanner) {
    const s = S.scanner; S.scanner = null;
    s.stop().catch(() => {});
  }
}

async function showScan() {
  $('#view').innerHTML = `
    <div class="page-head">
      <div><h1>Gate scanner</h1><p>Point the camera at a pass. Only this app can verify tickets — the check happens against the server's secret.</p></div>
      <div class="btn-row">
        <button class="btn btn-ghost btn-sm" id="scan-start">Start camera</button>
        <button class="btn btn-ghost btn-sm" id="scan-stop">Stop</button>
      </div>
    </div>
    <div class="scan-layout">
      <div>
        <div id="qr-reader"></div>
        <div class="scan-state" id="scan-state">Camera is off. Press <b>Start camera</b>, or paste a code manually below.</div>
        <div class="card" style="margin-top:14px">
          <h3 style="margin-bottom:10px">Manual code entry</h3>
          <div class="field"><input id="manual-code" placeholder="Paste the ticket code here…" autocomplete="off"></div>
          <button class="btn btn-block" id="manual-btn">Verify code</button>
        </div>
      </div>
      <div>
        <div id="scan-result"><div class="result-idle">No scan yet.<br>Results appear here.</div></div>
        <div class="card" style="margin-top:14px">
          <h3>Recent scans</h3>
          <ul class="scan-log" id="scan-log"><li>Loading…</li></ul>
        </div>
      </div>
    </div>`;

  $('#scan-start').addEventListener('click', startScanner);
  $('#scan-stop').addEventListener('click', () => { stopScanner(); $('#scan-state').textContent = 'Camera stopped.'; });
  $('#manual-btn').addEventListener('click', async () => {
    const code = $('#manual-code').value.trim();
    if (!code) return toast('Paste a ticket code first.', 'err');
    await verifyAndShow(code);
    $('#manual-code').value = '';
  });
  $('#manual-code').addEventListener('keydown', e => { if (e.key === 'Enter') $('#manual-btn').click(); });
  refreshScanLog();
}

async function startScanner() {
  if (typeof Html5Qrcode === 'undefined') {
    $('#scan-state').textContent = 'Scanner library failed to load. Use manual code entry below.';
    return;
  }
  stopScanner();
  const qr = new Html5Qrcode('qr-reader');
  S.scanner = qr;
  $('#scan-state').textContent = 'Starting camera…';
  try {
    await qr.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 260, height: 260 } },
      onScanFrame,
      () => {}
    );
    $('#scan-state').textContent = 'Camera live — point at a ticket QR.';
  } catch (e) {
    S.scanner = null;
    $('#scan-state').innerHTML = 'Camera unavailable: ' + esc(e.message || e) +
      '<br><br>Tip: browsers only allow the camera on <b>https://</b> or <b>localhost</b>. You can still paste a code manually below.';
  }
}

async function onScanFrame(decodedText) {
  const now = Date.now();
  if (decodedText === S.lastScan.code && now - S.lastScan.at < 3000) return; // debounce
  S.lastScan = { code: decodedText, at: now };
  await verifyAndShow(decodedText);
}

async function verifyAndShow(code) {
  let r;
  try { r = await api('POST', '/api/verify', { payload: code }); }
  catch (e) { return toast(e.message, 'err'); }

  const box = $('#scan-result');
  if (r.status === 'valid') {
    box.innerHTML = `<div class="result-banner valid">
      <div class="verdict">✓ ADMIT</div>
      <div class="detail"><b>${esc(r.ticket.type)}</b> pass${r.ticket.holder ? ' · ' + esc(r.ticket.holder) : ''}<br>
      ${esc(r.event.name)} · ${esc(r.ticket.id)}</div></div>`;
  } else if (r.status === 'already_used') {
    const when = r.ticket.usedAt ? new Date(r.ticket.usedAt).toLocaleString() : 'earlier';
    box.innerHTML = `<div class="result-banner already_used">
      <div class="verdict">⚠ ALREADY USED</div>
      <div class="detail">This pass was already scanned in <b>${esc(when)}</b>.<br>
      ${esc(r.ticket.type)}${r.ticket.holder ? ' · ' + esc(r.ticket.holder) : ''} · ${esc(r.ticket.id)}<br>
      Do not admit again without checking ID.</div></div>`;
  } else if (r.status === 'revoked') {
    box.innerHTML = `<div class="result-banner revoked">
      <div class="verdict">✕ REVOKED</div>
      <div class="detail">This pass was revoked by the host.<br>${esc(r.ticket.id)}</div></div>`;
  } else {
    const why = r.reason === 'forged_or_tampered' ? 'Signature check failed — this code was forged or edited.'
      : 'This is not a Gatekeeper ticket code.';
    box.innerHTML = `<div class="result-banner invalid">
      <div class="verdict">✕ INVALID</div>
      <div class="detail">${esc(why)}</div></div>`;
  }
  refreshScanLog();
}

async function refreshScanLog() {
  try {
    const d = await api('GET', '/api/scans?limit=20');
    const el = $('#scan-log');
    if (!el) return;
    el.innerHTML = d.scans.map(s => {
      const label = { valid: 'Admitted', already_used: 'Duplicate', revoked: 'Revoked', invalid: 'Invalid' }[s.status] || s.status;
      return `<li><span><span class="dot ${esc(s.status)}"></span>${esc(label)}</span>
        <span style="color:var(--muted);font-family:ui-monospace,monospace;font-size:11px">${esc((s.ticketId || '—').slice(0, 12))}</span></li>`;
    }).join('') || '<li>No scans yet.</li>';
  } catch (e) { /* ignore */ }
}

document.addEventListener('DOMContentLoaded', boot);
