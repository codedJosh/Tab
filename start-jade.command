#!/bin/zsh

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
APP_URL="http://127.0.0.1:8787/"

cd "$BACKEND_DIR"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed yet."
  echo "Install Node.js, then run this launcher again."
  exit 1
fi

if [ ! -d "$BACKEND_DIR/node_modules" ]; then
  echo "Installing backend dependencies..."
  npm install
fi

echo "Opening JADE in your browser..."
open "$APP_URL"

echo "Starting JADE backend..."
npm run dev
