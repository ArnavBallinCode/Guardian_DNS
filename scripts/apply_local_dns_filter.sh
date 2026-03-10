#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${1:-Wi-Fi}"
API_URL="${2:-http://127.0.0.1:8000}"

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required: https://brew.sh"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required"
  exit 1
fi

BREW_PREFIX="$(brew --prefix)"
DNSMASQ_CONF_DIR="$BREW_PREFIX/etc/dnsmasq.d"
DNSMASQ_MAIN_CONF="$BREW_PREFIX/etc/dnsmasq.conf"
GUARDIAN_CONF="$DNSMASQ_CONF_DIR/guardian.conf"
TMP_DOMAINS="/tmp/guardian-domains.txt"

echo "[1/7] Installing dnsmasq (if missing)..."
brew list dnsmasq >/dev/null 2>&1 || brew install dnsmasq

mkdir -p "$DNSMASQ_CONF_DIR"

echo "[2/7] Configuring upstream DNS forwarders (CRITICAL for internet access)..."
# Without upstream forwarders, dnsmasq can't resolve non-blocked domains
# and ALL DNS queries will fail, breaking internet access entirely.
UPSTREAM_CONF="$DNSMASQ_CONF_DIR/upstream.conf"
cat > "$UPSTREAM_CONF" <<'UPSTREAM'
# Guardian DNS — upstream forwarders
# These ensure non-blocked domains still resolve normally.
server=8.8.8.8
server=8.8.4.4
server=1.1.1.1
# Don't use /etc/resolv.conf (avoids loops when DNS points to 127.0.0.1)
no-resolv
# Only listen on localhost
listen-address=127.0.0.1
# Don't bind to wildcard — prevents port conflicts
bind-interfaces
# Cache for performance
cache-size=1000
# Log every DNS query so Guardian can auto-classify browsed domains in real time
log-queries
# Write queries to a dedicated log file so Guardian can tail it reliably
# (macOS unified log stream is unreliable for root-owned dnsmasq)
log-facility=/tmp/dnsmasq.log
UPSTREAM
echo "  → Wrote upstream config: $UPSTREAM_CONF"

echo "[3/7] Exporting permanent blocked domains from $API_URL ..."
curl -fsSL "$API_URL/export/domains.txt" -o "$TMP_DOMAINS"
DOMAIN_COUNT=$(wc -l < "$TMP_DOMAINS" | tr -d ' ')
echo "  → Downloaded $DOMAIN_COUNT domain(s)"

echo "[4/7] Building dnsmasq block rules..."
# Only write block rules, upstream config is separate
awk '{ if (length($0) > 0) print "address=/" $0 "/0.0.0.0" }' "$TMP_DOMAINS" > "$GUARDIAN_CONF"
echo "  → Wrote block rules: $GUARDIAN_CONF"

echo "[5/7] Ensuring dnsmasq includes custom conf dir..."
if ! grep -q '^conf-dir=.*dnsmasq.d' "$DNSMASQ_MAIN_CONF"; then
  echo "conf-dir=$DNSMASQ_CONF_DIR,*.conf" >> "$DNSMASQ_MAIN_CONF"
fi

echo "[6/7] Restarting dnsmasq service (requires root to bind port 53)..."
# Must stop AND start with sudo — dnsmasq runs as root (port 53 is privileged).
# A plain `brew services stop` (no sudo) silently fails when the service is
# root-owned, so the old config stays loaded.
sudo brew services stop dnsmasq 2>/dev/null || true
sleep 1
sudo brew services start dnsmasq
sleep 2

# Verify dnsmasq is actually resolving before changing system DNS
echo "  → Verifying dnsmasq can resolve external domains..."
if dig +short +time=5 +tries=3 google.com @127.0.0.1 | grep -qE '[0-9]{1,3}\.[0-9]{1,3}'; then
  echo "  → ✓ dnsmasq is resolving correctly"
else
  echo "  → ⚠ WARNING: dnsmasq may not be resolving. Skipping DNS switch for safety."
  echo "  → Check: brew services list | grep dnsmasq"
  echo "  → Check: dig google.com @127.0.0.1"
  exit 1
fi

echo "[7/7] Pointing macOS network service '$SERVICE_NAME' to local DNS..."
networksetup -setdnsservers "$SERVICE_NAME" 127.0.0.1

echo
echo "✅ Guardian DNS filter is active on service: $SERVICE_NAME"
echo "   Upstream DNS: 8.8.8.8 / 8.8.4.4 / 1.1.1.1"
echo "   Block rules: $GUARDIAN_CONF"
echo "   Upstream config: $UPSTREAM_CONF"
echo "   DNS query logging: ENABLED (log-queries)"
echo ""
echo "Verify:"
echo "  dig google.com @127.0.0.1    # should return real IP"
echo "  dig <blocked>.com @127.0.0.1 # should return 0.0.0.0"
echo ""
echo "Every domain you browse will now appear automatically in the Guardian"
echo "reviewer queue at http://127.0.0.1:8000/ui/reviewer (Live Review Queue tab)"
