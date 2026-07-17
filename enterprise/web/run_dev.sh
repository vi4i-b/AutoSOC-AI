#!/usr/bin/env bash
# Dev-server launcher for the preview tooling — self-contained so it does not
# depend on launch.json env/cwd support.
set -e
export PATH="/home/jalil/.local/node/bin:$PATH"
export VITE_API_BASE="${VITE_API_BASE:-http://127.0.0.1:8901}"
cd "$(dirname "$0")"
exec npm run dev -- --host 127.0.0.1 --port 5174
