#!/bin/sh
set -e

DATA_DIR="${SENTINEL_DATA:-/data}"
mkdir -p "$DATA_DIR"

# If config.json does not exist, initialize Sentinel backend
if [ ! -f "$DATA_DIR/config.json" ]; then
    echo "============================================================"
    echo "===> Initializing Sentinel backend in $DATA_DIR..."
    python server.py --data-dir "$DATA_DIR" init
    echo "============================================================"
    echo "===> IMPORTANT: Copy and save the ADMIN TOKEN shown above!"
    echo "============================================================"
else
    echo "===> Existing Sentinel configuration and database found in $DATA_DIR."
fi

# Pre-register default device if specified in environment
if [ -n "$SENTINEL_DEFAULT_DEVICE" ]; then
    echo "===> Registering default device: $SENTINEL_DEFAULT_DEVICE..."
    if [ -n "$SENTINEL_DEFAULT_TOKEN" ]; then
        python server.py --data-dir "$DATA_DIR" register "$SENTINEL_DEFAULT_DEVICE" --token "$SENTINEL_DEFAULT_TOKEN"
    else
        python server.py --data-dir "$DATA_DIR" register "$SENTINEL_DEFAULT_DEVICE"
    fi
fi

echo "===> Starting Sentinel backend on ${HOST:-0.0.0.0}:${PORT:-8000}..."
exec python server.py --data-dir "$DATA_DIR" serve --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
