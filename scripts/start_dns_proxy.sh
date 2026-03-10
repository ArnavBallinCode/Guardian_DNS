#!/usr/bin/env bash
# Guardian DNS Proxy starter
# Usage: bash scripts/start_dns_proxy.sh [Wi-Fi]
set -euo pipefail

SERVICE_NAME="${1:-Wi-Fi}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$SCRIPT_DIR/.venv/bin/python3"

if [[ ! -f "$PYTHON" ]]; then
  echo "ERROR: venv not found at $SCRIPT_DIR/.venv — run: python3 -m venv .venv && pip install -r requirements.txt"
  exit 1
fi

echo "[1/3] Stopping dnsmasq (if running) to free port 53..."
sudo brew services stop dnsmasq 2>/dev/null || true
# Also kill any stray dnsmasq processes
sudo pkill -f dnsmasq 2>/dev/null || true
sleep 1

echo "[2/3] Verifying port 53 is free..."
if sudo lsof -i UDP:53 2>/dev/null | grep -v mDNSResponder | grep -q LISTEN; then
  echo "ERROR: Something else is still on port 53:"
  sudo lsof -i UDP:53 2>/dev/null
  exit 1
fi

echo "[3/3] Starting Guardian DNS proxy (will prompt for sudo password)..."
echo ""
echo "  Keep this terminal open!"
echo "  The proxy will intercept all DNS queries and feed them to the reviewer queue."
echo ""
echo "  After it starts, set your Wi-Fi DNS in a NEW terminal:"
echo "    networksetup -setdnsservers $SERVICE_NAME 127.0.0.1"
echo ""
echo "  To undo later:"
echo "    Ctrl-C here, then: networksetup -setdnsservers $SERVICE_NAME empty"
echo ""

exec sudo "$PYTHON" "$SCRIPT_DIR/run_dns_proxy.py"
