#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$HOME/.local/share/samples_push/venv"
MARKER="$VENV_DIR/.installed"
REQ="$SCRIPT_DIR/requirements.txt"

# Create venv if missing
if [ ! -d "$VENV_DIR" ]; then
    echo "[setup] Creating venv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
fi

# Re-install if requirements changed or marker missing
if [ ! -f "$MARKER" ] || [ "$REQ" -nt "$MARKER" ]; then
    echo "[setup] Installing dependencies..."
    "$VENV_DIR/bin/pip" install -q --upgrade pip
    "$VENV_DIR/bin/pip" install -q -r "$REQ"
    touch "$MARKER"
fi

# Copy .env.example if .env is missing
if [ ! -f "$SCRIPT_DIR/.env" ] && [ -f "$SCRIPT_DIR/.env.example" ]; then
    echo "[setup] Created .env from .env.example — edit it before running."
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    exit 1
fi

exec "$VENV_DIR/bin/python" -m samples_push "$@"
