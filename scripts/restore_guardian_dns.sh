#!/usr/bin/env bash
# restore_guardian_dns.sh
# ========================
# Run this AFTER connecting ExpressVPN via Tunnelblick.
#
# Problem: Tunnelblick pushes ExpressVPN's DNS (e.g. 10.12.0.1) via the VPN
# interface, which overrides macOS DNS and bypasses Guardian's proxy on 127.0.0.1.
#
# Fix: Re-assert 127.0.0.1 as the Wi-Fi DNS so ALL queries hit Guardian first.
# Guardian auto-detects 10.12.0.1 at startup and still forwards through ExpressVPN.
#
# Usage (manual, after VPN connects):
#   sudo bash scripts/restore_guardian_dns.sh
#
# To make it run automatically on every VPN connect, add it as a
# Tunnelblick "connected" script:
#   1. Open Tunnelblick → click your VPN config → Advanced
#   2. Under "VPN Details" → "Scripts" tab
#   3. Set "Connected" script to this file
#   (or copy it to ~/Library/Application Support/Tunnelblick/Configurations/<name>.tblk/connected.sh)

set -euo pipefail

SERVICE="${1:-Wi-Fi}"

echo "[guardian] Setting $SERVICE DNS → 127.0.0.1 (Guardian proxy)"
networksetup -setdnsservers "$SERVICE" 127.0.0.1

echo "[guardian] Flushing DNS cache..."
dscacheutil -flushcache
killall -HUP mDNSResponder 2>/dev/null || true

# Show what DNS is now active
CURRENT=$(networksetup -getdnsservers "$SERVICE")
echo "[guardian] DNS for $SERVICE is now: $CURRENT"
echo ""
echo "Flow: Browser → Guardian (127.0.0.1:53) → ExpressVPN DNS → Internet"
echo "Blocking is active. Run 'networksetup -setdnsservers Wi-Fi empty' to stop."
