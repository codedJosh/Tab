# Hummingbird Tab System

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
2. Add `DATABASE_URL`, `JADE_SESSION_SECRET`, and optional `JADE_WORKSPACE_ID`
3. Run `npm install`
4. Run `npm run dev` or double-click `start-jade.command`
5. Open `http://127.0.0.1:8787/`
6. On a brand-new local workspace, create the first account through the sign-up form. That first local account becomes the first System Manager.

## Checks

Run this before deploys when you want a quick sanity pass:

```bash
npm run check
```

## Netlify

This repo now includes a root `netlify.toml` that publishes `frontend/`.

Recommended settings:

- Base directory: leave blank
- Publish directory: leave blank if Netlify reads `netlify.toml`, otherwise set `frontend`
- Build command: leave blank
