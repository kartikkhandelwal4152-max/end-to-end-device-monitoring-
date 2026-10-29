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

# Pre-register additional devices if specified (comma-separated: DEVICE-01,DEVICE-02)
if [ -n "$SENTINEL_EXTRA_DEVICES" ]; then
    echo "===> Registering additional devices..."
    echo "$SENTINEL_EXTRA_DEVICES" | tr ',' '\n' | while read -r dev; do
        dev=$(echo "$dev" | tr -d ' \r\n')
        if [ -n "$dev" ]; then
            echo "--- Registering $dev ---"
            python server.py --data-dir "$DATA_DIR" register "$dev"
        fi
    done
fi

# Seed all known devices with their permanent tokens on startup
python server.py --data-dir "$DATA_DIR" register "shlok_laptop" --token "f2UUFNDtcLGzanLuy0AJGCFYCrxnvYX4jhry1uRH3gs" || true
python server.py --data-dir "$DATA_DIR" register "kartavya_Laptop" --token "LulBkckumzh1a-NlbCQbRJCOfDGOc8h-zMZPxwxwOIY" || true
python server.py --data-dir "$DATA_DIR" register "RAGHAV-LAPTOP" --token "gLB9ERyjahBpfF9erZHc3btwEL2L1zto2SmNlCgaoaU" || true
python server.py --data-dir "$DATA_DIR" register "tanisha_laptop" --token "4GX6pkoLlNOH9IZszLG_JHDJD8n596UyPOUuS1cj4_s" || true

echo "===> Starting Sentinel backend on ${HOST:-0.0.0.0}:${PORT:-8000}..."
exec python server.py --data-dir "$DATA_DIR" serve --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
