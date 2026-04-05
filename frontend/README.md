# Hummingbird Frontend

This folder is the static frontend publish target for Hummingbird Tab System.

`frontend/index.html` is the only website frontend source of truth in this repo.

Deploy this folder to Netlify, not the project root.

## Files

- `index.html`
- `app.js`
- `styles.css`
- `jade-logo.jpg`
- `backend-config.js`
- `netlify.toml`

## Before deploying

Edit `backend-config.js` so it points to your hosted backend:

```js
window.JADE_BACKEND_URL = "https://your-backend-host/api";
```

## Netlify settings

- Base directory: `frontend`
- Publish directory: `.`
- Build command: leave blank

## Notes

- This frontend is static only.
- The backend must already be running on a normal Node host.
- The frontend and backend can live on different domains.
- The root `index.html` is only a local launcher page now, not a second app copy.
