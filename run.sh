#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$HOME/.local/share/samples_push"
VENV_DIR="$DATA_DIR/venv"
MARKER="$VENV_DIR/.installed"
REQ="$SCRIPT_DIR/requirements.txt"
ENV_FILE="$DATA_DIR/.env"

# Create data dir if missing
mkdir -p "$DATA_DIR"

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

# Copy .env.example if .env is missing in data dir
if [ ! -f "$ENV_FILE" ] && [ -f "$SCRIPT_DIR/.env.example" ]; then
    echo "[setup] Created .env at $ENV_FILE — edit it before running."
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
    exit 1
fi

cd "$SCRIPT_DIR"
exec "$VENV_DIR/bin/python" -m samples_push "$@"
