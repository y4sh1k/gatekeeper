# Gatekeeper — Secure Ticket Passes 🎟️

Every ticket gets a **custom, cryptographically sealed QR** that only this app
can create and only this app can verify. The host — and only the host — can
issue passes and scan people in at the gate.

## How the security works

- **Unforgeable QRs.** Each QR contains `GK1.<eventId>.<ticketId>.<signature>`,
  where the signature is an HMAC-SHA256 computed with a 256-bit secret that is
  generated on first run and **never leaves the server**. Editing a QR by hand,
  screenshotting someone else's format, or inventing a code all fail the
  signature check — verified with a timing-safe comparison.
- **App-only verification.** A generic QR scanner just sees an opaque string.
  Only this app (which holds the secret) can answer "is this ticket real?",
  and the `/api/verify` endpoint requires a host login.
- **Single-use passes.** The server records the first scan. Any later scan of
  the same QR shows **ALREADY USED** with the original check-in time — so a
  photographed/copied QR only works once. First scan wins.
- **Host-only access.** All creation, management, and scanning endpoints sit
  behind a host password (scrypt-hashed), an httpOnly + SameSite session
  cookie, and login rate-limiting. There is no public sign-up and no guest role.
- **Revocation.** The host can revoke any pass instantly — it will fail at the
  gate from that moment on.

> Honest caveat: no QR system can stop someone *photographing a valid,
> unused* QR and using the photo before the real holder arrives. Gatekeeper
> mitigates this the way real venues do: single-use scanning, host-only
> scanning at the door, per-pass holder names shown on the scanner screen, and
> instant revocation.

## Run it locally

```bash
npm install
npm start
# open http://localhost:3000
```

On first visit you'll create your **host password**. That's the only account —
guard it.

## Put it online

The camera scanner needs **https://** (browsers block the camera on plain
http). Two paths — pick one:

### Path A — Render Blueprint, set-and-forget (~$7.25/mo)

1. Push this folder to a GitHub repo (commands below).
2. On Render: **New → Blueprint**, paste your repo URL, **Apply**.
   `render.yaml` in this folder sets everything up: the Node service, a
   health check, and a 1 GB persistent disk at `/var/data`, so your events,
   passes, and the signing secret survive redeploys.
3. Open your `https://…onrender.com` URL, create the host password, done.
   (The Starter plan is required for the persistent disk; the disk itself is
   $0.25/GB/month.)

### Path B — Render free ($0, with one habit)

1. Same repo, but create the web service manually as a **Free** instance
   (skip the Blueprint — free services can't attach disks).
2. Two catches: free services sleep after 15 min idle (first visitor waits
   ~30–60 s for it to wake), and **redeploys wipe the data**. The fix is the
   **Backup** card on the dashboard: hit *Download backup* before you push any
   update, then *Restore backup* after the deploy. Ten seconds, zero loss.

### Getting the code onto GitHub

```bash
cd gatekeeper
git init -b main
git add .
git commit -m "Gatekeeper ticket app"
# create an empty repo on github.com (no README), then:
git remote add origin https://github.com/YOU/gatekeeper.git
git push -u origin main
```

Railway works too (volumes on the Hobby plan); the only thing the app needs
is Node 18+, `npm start`, and a persistent `DATA_DIR`.

## Using it

1. **Events** → New event (name, date, venue).
2. Open the event → **Issue new passes** (quantity + type like VIP/General,
   optional holder name for single passes).
3. Click **QR** on any pass for its custom styled code — download the PNG to
   send to the guest, or **Print** a batch of ticket cards for the door.
4. At the gate, open **Scanner** (host login required), point the camera at a
   pass. Green **ADMIT** = let them in; amber **ALREADY USED** = duplicate;
   red **INVALID** = forged.

## Files

- `server.js` — Express API, HMAC signing, host auth, JSON database
- `public/` — the host app (dashboard, ticket manager, scanner)
- `public/vendor/` — QR styling + camera scanner libraries (vendored, work offline)
- `data/` — database + signing secret (created on first run; **back this up**)

## Notes

- Storage is a small atomic JSON file — perfect for small/medium events.
  For thousands of guests, swap in Postgres.
- Forgot the host password? Stop the server, delete `data/db.json`, restart,
  and create a new one (you'll lose events/tickets — or restore from backup).
- Back up `data/` regularly. The `.secret` file is what makes old QRs verify —
  lose it and every issued pass becomes invalid.
