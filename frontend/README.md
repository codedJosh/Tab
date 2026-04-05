# Hummingbird Frontend

This folder is the static frontend publish target for Hummingbird Tab System.

Deploy this folder to Netlify, not the project root.

## Files

- `index.html`
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
