# JADE Hummingbird

This repository is split into:

- the backend at the repository root
- the static frontend in `frontend/`

## Backend

Key files:

- `server.mjs`
- `package.json`
- `schema.sql`
- `start-jade.command`
- `scripts/check.mjs`

This backend is a Node + Express service backed by PostgreSQL.

On startup, the backend now auto-checks the workspace schema and adds revision/history storage if the database is older than the current code.

## Frontend

Netlify should publish the `frontend/` directory. `frontend/index.html` is the live website source of truth.

Key files:

- `frontend/index.html`
- `frontend/app.js`
- `frontend/styles.css`
- `frontend/jade-logo.jpg`
- `frontend/backend-config.js`
- `index.html` (thin local launcher only)

Before deploying the frontend, set the backend URL in `frontend/backend-config.js`:

```js
window.JADE_BACKEND_URL = "https://your-backend-host/api";
```

## Local use

1. Create PostgreSQL and run `schema.sql`
2. Add:
   - required: `DATABASE_URL`, `JADE_SESSION_SECRET`
   - optional database SSL override: `DATABASE_SSL=true` or `DATABASE_SSL=false`
   - optional: `JADE_WORKSPACE_ID`
   - recommended performance limits: `DATABASE_POOL_MAX=4`, `API_CONCURRENCY=2`
   - optional request controls: `API_QUEUE_LIMIT=24`, `MAX_BODY_SIZE=30mb`
   - optional history controls: `WORKSPACE_HISTORY_INTERVAL=25`, `WORKSPACE_HISTORY_LIMIT=10`
   - optional diagnostics: `SLOW_REQUEST_MS=2500`, `MEMORY_WARNING_MB=400`
   - optional email delivery (Resend): `RESEND_API_KEY`, `RESEND_FROM_EMAIL`
   - optional email behavior: `RESEND_REPLY_TO` (defaults to `hummingbird@myjade.org`), `PRIVATE_LINK_EMAIL_COOLDOWN_MINUTES` (defaults to `10`), `PUBLIC_APP_URL`
3. Run `npm install`
4. Run `npm run dev` or double-click `start-jade.command`
5. Open `http://127.0.0.1:8787/`
6. On a brand-new local workspace, create the first account through the sign-up form. That first local account becomes the first System Manager.

## Checks

Run this before deploys when you want a quick sanity pass:

```bash
npm run check
```

## Private URL Email Delivery

When Resend environment variables are configured, JADE now sends account private URL emails on:

- self sign-up
- debater registration
- judge registration
- manager/admin roster updates persisted to the backend

It also supports manual resend from Private Links / People via the `send_private_link_email` backend action.

## Netlify

This repo now includes a root `netlify.toml` that publishes `frontend/`.

Recommended settings:

- Base directory: leave blank
- Publish directory: leave blank if Netlify reads `netlify.toml`, otherwise set `frontend`
- Build command: leave blank

## Render Backend

For the web service, use the repo root with:

- Build command: `npm install`
- Start command: `npm start`
- Required env vars: `DATABASE_URL`, `JADE_SESSION_SECRET`
- Recommended: use the Render Postgres internal URL when the database and web service are in the same Render region.

The server auto-creates the JADE tables on startup. If Render logs `Connection terminated unexpectedly` before a port opens, check the database URL and SSL mode first:

- Internal Render Postgres URL: set `DATABASE_SSL=false` if your connection is being forced through TLS.
- External Render Postgres URL: set `DATABASE_SSL=true`, or include `sslmode=require` in the URL.

For a small or medium Render instance, keep `DATABASE_POOL_MAX=4` and
`API_CONCURRENCY=2`. The API concurrency gate prevents several full workspace
uploads from being parsed and persisted simultaneously. `/api/health` reports
RSS/heap and database-pool usage, while slow or high-memory requests are logged
as `JADE runtime warning` entries.
