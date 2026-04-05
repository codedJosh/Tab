#!/bin/zsh

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend"

mkdir -p "$FRONTEND_DIR"

if [ -f "$ROOT_DIR/jade-logo.jpg" ]; then
  cp "$ROOT_DIR/jade-logo.jpg" "$FRONTEND_DIR/jade-logo.jpg"
fi

if [ -f "$ROOT_DIR/jade-hummingbird-mark.svg" ]; then
  cp "$ROOT_DIR/jade-hummingbird-mark.svg" "$FRONTEND_DIR/jade-hummingbird-mark.svg"
fi

echo "Shared assets synced to $FRONTEND_DIR"
echo "frontend/index.html remains the only website source of truth."
