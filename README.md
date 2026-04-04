# JADE Debate Tab

This repository is split into:

- the backend at the repository root
- the static frontend in `frontend/`

## Backend

Key files:

- `server.mjs`
- `package.json`
- `schema.sql`

This backend is a Node + Express service backed by PostgreSQL.

## Frontend

Netlify should publish the `frontend/` directory.

Key files:

- `frontend/index.html`
- `frontend/jade-logo.jpg`
- `frontend/backend-config.js`

Before deploying the frontend, set the backend URL in `frontend/backend-config.js`:

```js
window.JADE_BACKEND_URL = "https://your-backend-host/api";
```

## Netlify

This repo now includes a root `netlify.toml` that publishes `frontend/`.

Recommended settings:

- Base directory: leave blank
- Publish directory: leave blank if Netlify reads `netlify.toml`, otherwise set `frontend`
- Build command: leave blank
