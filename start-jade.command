#!/bin/zsh

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_URL="http://127.0.0.1:8787/"

cd "$ROOT_DIR"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed yet."
  echo "Install Node.js, then run this launcher again."
  exit 1
fi

if [ ! -d "$ROOT_DIR/node_modules" ]; then
  echo "Installing JADE Hummingbird backend dependencies..."
  npm install
fi

echo "Starting JADE Hummingbird backend..."
npm run dev &
SERVER_PID=$!

cleanup() {
  if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

echo "Waiting for JADE Hummingbird to come online..."
for _ in {1..30}; do
  if curl -fsS "$APP_URL" >/dev/null 2>&1; then
    echo "Opening JADE Hummingbird in your browser..."
    open "$APP_URL"
    wait "$SERVER_PID"
    exit $?
  fi
  sleep 1
done

echo "JADE Hummingbird did not respond at $APP_URL in time."
exit 1
