#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${1:-Wi-Fi}"

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required: https://brew.sh"
  exit 1
fi

BREW_PREFIX="$(brew --prefix)"
GUARDIAN_CONF="$BREW_PREFIX/etc/dnsmasq.d/guardian.conf"
UPSTREAM_CONF="$BREW_PREFIX/etc/dnsmasq.d/upstream.conf"

echo "[1/4] Restoring automatic DNS for '$SERVICE_NAME' FIRST..."
# Restore DNS before touching dnsmasq so internet isn't interrupted
networksetup -setdnsservers "$SERVICE_NAME" empty

echo "[2/4] Removing guardian dnsmasq block rules..."
rm -f "$GUARDIAN_CONF"

echo "[3/4] Removing guardian upstream config..."
rm -f "$UPSTREAM_CONF"

echo "[4/4] Restarting dnsmasq service..."
brew services restart dnsmasq

echo
echo "✅ Guardian DNS filter removed from service: $SERVICE_NAME"
echo "   DNS restored to automatic (DHCP) settings."
