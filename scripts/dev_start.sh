#!/bin/bash
# 1-Click Native Start Script for DocSign (MacBook 8GB RAM Optimized)
# Starts FastAPI Backend (port 8000) and React Vite Frontend (port 5173) natively.

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$DIR"

echo "=========================================================="
echo "🚀 STARTING DOCSIGN NATIVE ENVIRONMENT (Apple Silicon)"
echo "   Mode: Native macOS (No Docker, ~180MB RAM total)"
echo "=========================================================="

# 1. Activate Python virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    ./venv/bin/pip install -r backend/requirements.txt
fi

source venv/bin/activate
export PYTHONPATH=.

# Ensure data directories exist
mkdir -p data/db data/storage/documents

# Run Alembic migrations if needed
./venv/bin/alembic upgrade head

# 2. Cleanup function on Ctrl+C
cleanup() {
    echo ""
    echo "🛑 Shutting down backend and frontend gracefully..."
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
    echo "✅ Shutdown complete. Goodbye!"
    exit 0
}
trap cleanup SIGINT SIGTERM

# 3. Start Backend in background
echo "⚡ Starting FastAPI Backend on http://localhost:8000 ..."
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --reload &
BACKEND_PID=$!

# 4. Start Frontend
echo "⚡ Starting Vite Frontend on http://localhost:5173 ..."
cd frontend
npm run dev -- --host localhost --port 5173 &
FRONTEND_PID=$!

echo ""
echo "✨ System is ready! Open your browser at: http://localhost:5173"
echo "   Press Ctrl+C to stop all services."
echo ""

wait
