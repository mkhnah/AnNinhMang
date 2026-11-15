#!/bin/bash
# Explicit opt-in. Backend private API and signer stay on localhost.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${DEMO_MODE:-LOCAL_DEMO}"
host="127.0.0.1"
if [ "$mode" = "LAN_DEMO" ]; then
    host="${DEMO_HOST:?Set DEMO_HOST to the actual MacBook LAN IP}"
elif [ "$mode" != "LOCAL_DEMO" ]; then
    echo 'DEMO_MODE must be LOCAL_DEMO or LAN_DEMO' >&2
    exit 1
fi
if [ ! -f frontend/dist/index.html ]; then
    echo 'Run npm run build --prefix frontend first' >&2
    exit 1
fi
exec venv/bin/uvicorn backend.app.public_demo:app --host "$host" --port "${DEMO_PORT:-5174}" --no-proxy-headers --no-access-log
