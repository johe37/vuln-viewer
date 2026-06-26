#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8080}"

cd "$(dirname "$0")"

echo "[+] Starting Vulnerability Viewer"
echo "[+] Serving on http://localhost:${PORT}"
echo "[+] Ctrl+C to stop"

python3 -m http.server "$PORT" -d ../
