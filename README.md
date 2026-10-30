# Aunty Lydia Schools: backend

One small Node server that serves the website **and** the API. No `npm install` needed (zero dependencies).
Requires **Node 22.13 or newer**.

## Run it

```bash
cd aunty-lydia-schools
npm start            # or: node server/server.js
```

Open http://localhost:3000. The admin is at http://localhost:3000/admin.html

On the first start the terminal prints a one-time admin password (or uses `ADMIN_PASSWORD` if you set it
in `server/.env`). Log in, then change it under **Backup & Security**.
Forgot it? `node server/server.js reset-password NewPassword123`

## What it does

| Feature | How |
| --- | --- |
| Public content (news, events, gallery, staff, fees, settings, announcement bar) | Stored in SQLite; pages load it from `/api/content.js` |
| Admin login | Server-checked password (scrypt), HttpOnly session cookie, 7-day expiry, 8 attempts / 15 min / IP |
| Photos | Admin uploads are checked (real JPG/PNG/WebP, max 4 MB) and saved as files in `server/data/uploads/` |
| Contact form + Admissions form | Saved in the database, shown in **Admin > Messages**, exportable to CSV |
| Spam protection | Hidden honeypot field + 10 submissions / hour / IP |
| Optional alerts | Set `NOTIFY_WEBHOOK_URL` and each new enquiry is POSTed there as JSON |

## API

Public: `GET /api/content`, `GET /api/content.js`, `POST /api/contact`, `POST /api/admissions`, `GET /api/health`
Auth: `POST /api/login`, `POST /api/logout`, `GET /api/session`
Admin (login required): `GET|PUT|DELETE /api/admin/content`, `POST /api/admin/password`,
`GET /api/admin/submissions`, `GET /api/admin/submissions.csv`, `PATCH|DELETE /api/admin/submissions/:id`

## Going live (checklist)

1. Host it anywhere that runs Node 22+ (a VPS, Render, Railway, Fly.io...). Start command: `npm start`.
2. **Put the `server/data` folder on a persistent disk/volume** (set `DATA_DIR` if needed). It holds the database and photos; everything is lost if the host wipes it.
3. Serve over HTTPS and set `COOKIE_SECURE=1`. If you are behind a proxy/CDN also set `TRUST_PROXY=1` (so rate limits see real visitor IPs).
4. Back up `server/data/` regularly (and use Admin > Backup for a content copy).
5. Run `npm test` after any change to the server.

## Notes

* Content saves replace the whole document (last save wins), which suits one or two editors.
* Opening the HTML files straight from disk (no server) still works as a preview: the site falls back to built-in sample content.
