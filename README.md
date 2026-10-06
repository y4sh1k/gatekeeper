# Gatekeeper v2 — Secure Ticket Passes 🎟️ (Vercel edition)

Every ticket gets a **custom, cryptographically sealed QR** that only this app
can create and only this app can verify. The host — and only the host — can
issue passes and scan people in at the gate.

This edition runs **serverless on Vercel**: the API is a single serverless
function (`api/`), static files come from Vercel's CDN, and all state lives in
**Vercel KV** (Redis). There is no server to keep awake and no disk to manage.

## How the security works

- **Unforgeable QRs.** Each QR contains `GK1.<eventId>.<ticketId>.<signature>`,
  where the signature is an HMAC-SHA256 computed with the `GATEKEEPER_SECRET`
  env var, which **never leaves the server**. Editing a QR by hand or inventing
  a code fails the signature check (timing-safe comparison).
- **App-only verification.** A generic QR scanner just sees an opaque string.
  Only this app can answer "is this ticket real?", and `/api/verify` requires
  a host login.
- **Single-use passes, race-safe.** Check-in claims the ticket with an atomic
  `SET NX` — even two scanners hitting the same code at the same instant can't
  both admit it. Later scans show **ALREADY USED** with the first check-in time.
- **Host-only access.** All endpoints sit behind a host password
  (scrypt-hashed), an httpOnly + SameSite session cookie (server-side, 24h
  TTL), and login rate-limiting. No public sign-up, no guest role.
- **Revocation.** Revoke any pass instantly — it fails at the gate from then on.

> Honest caveat: no QR system can stop someone *photographing a valid,
> unused* QR and using the photo before the real holder arrives. Gatekeeper
> mitigates this the way real venues do: single-use scanning, host-only
> scanning at the door, per-pass holder names on the scanner screen, and
> instant revocation.

## Deploy on Vercel

The repo is already on GitHub. In your Vercel dashboard:

1. **Import the repo** (`y4sh1k/gatekeeper`) as a new project and deploy.
   The first deploy will show a setup screen — that's expected, keep going.
2. **Add storage:** open the project → **Storage** tab → **Create Database**
   → **KV** → Continue → connect it to this project. (This gives the app its
   ticket database.)
3. **Add the secret:** **Settings** → **Environment Variables** → add
   `GATEKEEPER_SECRET` = 64 hex characters (generate with
   `openssl rand -hex 32`, or use the generator on the app's setup screen).
4. **Deployments** tab → **Redeploy** so the new env var takes effect.
5. Open your `https://…vercel.app` URL, create the **host password**, done.

Then: Events → New event → issue passes → **Scanner** at the gate. The
dashboard also has one-click **Backup / Restore** (download all data as JSON).

## Run it locally

```bash
npm install
# EITHER: in-memory backend (no network needed, data resets on restart)
GK_MEMORY_STORE=1 npm start
# OR: real KV — copy .env.example to .env and fill in the values
npm start
# open http://localhost:3000
```

## Files

- `server.js` — Express API (exported for serverless; runs standalone locally)
- `api/[[...route]].js` — Vercel serverless entry, routes all `/api/*` here
- `store.js` — storage layer: Vercel KV in production, in-memory with
  `GK_MEMORY_STORE=1`
- `public/` — the host app (dashboard, ticket manager, scanner, setup screens)
- `public/vendor/` — QR styling library vendored (works offline); the camera
  scanner library falls back to CDN if the vendored copy is absent

## Notes

- Forgot the host password? There is no password reset by design — restore
  from a dashboard **Backup** instead (it includes the host record).
- Back up `GATEKEEPER_SECRET` somewhere safe. Losing it invalidates every
  pass ever issued.
- Prefer a traditional always-on server? The v1 branch of this app
  (`server.js` + JSON file store + `render.yaml`) runs on Render/Railway with
  zero external services.
