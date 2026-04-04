#!/bin/zsh

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend"

mkdir -p "$FRONTEND_DIR"

cp "$ROOT_DIR/index.html" "$FRONTEND_DIR/index.html"
cp "$ROOT_DIR/jade-logo.jpg" "$FRONTEND_DIR/jade-logo.jpg"

if [ ! -f "$FRONTEND_DIR/backend-config.js" ]; then
  cp "$ROOT_DIR/backend-config.js" "$FRONTEND_DIR/backend-config.js"
fi

echo "Frontend files synced to $FRONTEND_DIR"
