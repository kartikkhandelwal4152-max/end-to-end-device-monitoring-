#!/bin/sh
set -e

DATA_DIR="${SENTINEL_DATA:-/data}"
mkdir -p "$DATA_DIR"

# If config.json does not exist, initialize Sentinel backend
if [ ! -f "$DATA_DIR/config.json" ]; then
    echo "============================================================"
    echo "===> Initializing Sentinel backend in $DATA_DIR..."
    : "${SENTINEL_ADMIN_PASSWORD:?Set an initial admin password privately before first container start}"
    python server.py --data-dir "$DATA_DIR" init >/dev/null
    echo "============================================================"
    echo "===> IMPORTANT: Sign in as admin with your configured initial password."
    echo "============================================================"
else
    echo "===> Existing Sentinel configuration and database found in $DATA_DIR."
fi

# Upgrade columns before indexes and before any registration.
python server.py --data-dir "$DATA_DIR" migrate
if [ -n "$SENTINEL_DEFAULT_DEVICE" ]; then
    python server.py --data-dir "$DATA_DIR" ensure-device "$SENTINEL_DEFAULT_DEVICE"
fi
if [ -n "$SENTINEL_EXTRA_DEVICES" ]; then
    echo "$SENTINEL_EXTRA_DEVICES" | tr ',' '\n' | while IFS= read -r dev; do
        if [ -n "$dev" ]; then
            SENTINEL_DEFAULT_TOKEN= python server.py --data-dir "$DATA_DIR" ensure-device "$dev"
        fi
    done
fi

echo "===> Starting Sentinel backend on ${HOST:-0.0.0.0}:${PORT:-8000}..."
exec python server.py --data-dir "$DATA_DIR" serve --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
