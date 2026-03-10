#!/usr/bin/env python3
"""
Guardian DNS Proxy
==================
Pure-Python DNS server. No dnsmasq. No log files. No external dependencies.

What it does:
  - Listens on UDP port 53 (127.0.0.1)
  - Every DNS query from your browser hits this first
  - Checks Guardian's SQLite DB directly — if domain is permanent_block → returns 0.0.0.0
  - Otherwise forwards to 8.8.8.8, returns the real answer
  - Fires a background POST to /api/review-queue/inject so Guardian auto-classifies
    every domain you visit via Ollama

Run (needs sudo for port 53):
  sudo .venv/bin/python3 run_dns_proxy.py

Then set Wi-Fi DNS to 127.0.0.1:
  networksetup -setdnsservers Wi-Fi 127.0.0.1

To stop:
  Ctrl-C, then: networksetup -setdnsservers Wi-Fi empty
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import struct
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

# Allow `from app.blocklist import ...` when run as a standalone script
sys.path.insert(0, str(Path(__file__).parent))
try:
    from app.blocklist import assess_domain_multi_signal
    _HAS_FAST_CHECK = True
except ImportError as _e:
    _HAS_FAST_CHECK = False
    print(f"[dns] WARNING: could not import app.blocklist ({_e}) — keyword/seed check disabled", flush=True)

# ── Config ────────────────────────────────────────────────────

LISTEN_HOST   = "127.0.0.1"
LISTEN_PORT   = 53
UPSTREAM_PORT = 53          # DNS is always port 53 — true for ExpressVPN, OpenVPN, Tunnelblick
UPSTREAM_TIMEOUT = 3.0


def _detect_vpn_dns() -> str:
    """
    Detect the upstream DNS Guardian should forward to.

    Chain of custody:
      1.  scutil --dns  — macOS system resolver, picks up ExpressVPN / Tunnelblick VPN DNS
      2.  /etc/resolv.conf — written by OpenVPN up-scripts (Tunnelblick writes this too)
      3.  8.8.8.8 fallback — used only when no VPN is active

    Skips 127.0.0.1 (would loop back into Guardian) and link-local addresses.
    """
    _SKIP = {"127.0.0.1", "::1"}

    # 1. scutil --dns — the authoritative macOS resolver database.
    #    ExpressVPN via Tunnelblick pushes its DNS (e.g. 10.12.0.1) here.
    try:
        import subprocess as _sp
        _r = _sp.run(["scutil", "--dns"], capture_output=True, text=True, timeout=2)
        for _line in _r.stdout.splitlines():
            _line = _line.strip()
            if _line.startswith("nameserver["):
                _ip = _line.split(":")[-1].strip()
                if _ip and _ip not in _SKIP and not _ip.startswith("169.254"):
                    return _ip
    except Exception:
        pass

    # 2. /etc/resolv.conf — OpenVPN up-scripts write this on connect
    try:
        with open("/etc/resolv.conf") as _f:
            for _line in _f:
                _parts = _line.strip().split()
                if len(_parts) >= 2 and _parts[0] == "nameserver":
                    _ip = _parts[1]
                    if _ip and _ip not in _SKIP and not _ip.startswith("169.254"):
                        return _ip
    except Exception:
        pass

    return "8.8.8.8"


UPSTREAM_HOST = _detect_vpn_dns()
GUARDIAN_API  = "http://127.0.0.1:8000"
DB_PATH       = Path(__file__).parent / "data" / "guardian.db"

# Same as settings.temp_threshold — keyword matches at or above this are temp-blocked
TEMP_THRESHOLD = 0.60

# Infrastructure / noisy domains — forward but never classify
_SKIP_SUFFIXES = (
    ".local", ".internal", ".lan", ".arpa", "localhost",
    ".apple.com.edgekey.net", ".akamaiedge.net", ".cloudfront.net",
    ".akadns.net", ".aaplimg.com",
)

# DNS record types
TYPE_A    = 1
TYPE_AAAA = 28

# Session dedup — avoid spamming the classifier with every repeated query
_injected: set[str] = set()
_injected_lock = threading.Lock()


# ── DNS packet parsing ────────────────────────────────────────

def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name at offset. Returns (name, next_offset)."""
    labels: list[str] = []
    jumped = False
    original_offset = offset
    jumps = 0

    while offset < len(data):
        length = data[offset]
        if length == 0:
            if not jumped:
                original_offset = offset + 1
            break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            jumped = True
            offset = ptr
            jumps += 1
            if jumps > 20:
                break
            continue
        else:
            offset += 1
            end = offset + length
            labels.append(data[offset:end].decode("ascii", errors="replace"))
            offset = end

    return ".".join(labels), original_offset


def _question_end(data: bytes, start: int = 12) -> int:
    """Return offset just after QTYPE+QCLASS (i.e. end of the question section)."""
    offset = start
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            offset += 2
            break
        else:
            offset += 1 + length
    return offset + 4  # QTYPE(2) + QCLASS(2)


def _get_qtype(data: bytes, start: int = 12) -> int:
    """Extract QTYPE from the question section."""
    offset = start
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            offset += 2
            break
        else:
            offset += 1 + length
    if offset + 2 <= len(data):
        return struct.unpack("!H", data[offset:offset + 2])[0]
    return 0


# ── DNS response builders ─────────────────────────────────────

def _block_response(query: bytes, qtype: int) -> bytes:
    """Build a DNS A/AAAA response pointing to 0.0.0.0 / :: (blocked)."""
    q_end = _question_end(query, 12)
    question_section = query[12:q_end]
    tid   = query[:2]
    flags = struct.pack("!H", 0x8180)   # QR=1 RD=1 RA=1 NOERROR
    hdr   = tid + flags + struct.pack("!HHHH", 1, 1, 0, 0)

    if qtype == TYPE_AAAA:
        answer = (
            struct.pack("!H", 0xC00C)   # NAME → pointer to offset 12
            + struct.pack("!H", 28)     # TYPE AAAA
            + struct.pack("!H", 1)      # CLASS IN
            + struct.pack("!I", 60)     # TTL
            + struct.pack("!H", 16)     # RDLENGTH
            + b"\x00" * 16             # ::
        )
    else:
        answer = (
            struct.pack("!H", 0xC00C)
            + struct.pack("!H", 1)      # TYPE A
            + struct.pack("!H", 1)      # CLASS IN
            + struct.pack("!I", 60)     # TTL
            + struct.pack("!H", 4)      # RDLENGTH
            + b"\x00\x00\x00\x00"      # 0.0.0.0
        )

    return hdr + question_section + answer


# ── Guardian DB check ─────────────────────────────────────────

def _is_blocked(domain: str) -> tuple[bool, str]:
    """
    Direct SQLite check — no HTTP round-trip needed.
    Returns (blocked, status) where blocked=True for both permanent_block
    and temporary_block (temporary blocks are active until a reviewer clears them).
    """
    if not DB_PATH.exists():
        return False, ""
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=0.5)
        row = conn.execute(
            "SELECT status FROM domain_policy WHERE domain = ?", (domain,)
        ).fetchone()
        conn.close()
        if row is None:
            return False, ""
        status = row[0]
        return status in ("permanent_block", "temporary_block"), status
    except Exception:
        return False, ""


def _fast_check(domain: str) -> tuple[bool, str, str, float]:
    """
    Instant seed-list + keyword check using app.blocklist (no LLM, no HTTP).
    Returns (should_block, db_status, category, risk).
    Called BEFORE forwarding — blocks on the very first visit for known-bad domains.
    """
    if not _HAS_FAST_CHECK:
        return False, "", "", 0.0
    try:
        risk, category, source = assess_domain_multi_signal(domain)
    except Exception:
        return False, "", "", 0.0
    if source == "seed_blocklist":
        return True, "permanent_block", category, 1.0
    if source == "keyword_heuristic" and risk >= TEMP_THRESHOLD:
        return True, "temporary_block", category, risk
    return False, "", "", 0.0


def _write_block(domain: str, status: str, category: str, risk: float) -> None:
    """
    Write a block decision directly to SQLite.
    Uses INSERT OR IGNORE so reviewer overrides are never lost.
    """
    if not DB_PATH.exists():
        return
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=1.0)
        review_required = 1 if status == "temporary_block" else 0
        conn.execute(
            """
            INSERT OR IGNORE INTO domain_policy
            (domain, status, category, p_risk, p_vote, combined_confidence, review_required)
            VALUES (?, ?, ?, ?, NULL, NULL, ?)
            """,
            (domain, status, category, risk, review_required),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[dns] db write error for {domain}: {exc}", file=sys.stderr, flush=True)


# ── Auto-classify new domains ─────────────────────────────────

def _inject(domain: str) -> None:
    """POST domain to Guardian's classifier queue so Ollama refines the verdict."""
    with _injected_lock:
        if domain in _injected:
            return
        _injected.add(domain)
    try:
        body = json.dumps({"domain": domain}).encode()
        req  = urllib.request.Request(
            f"{GUARDIAN_API}/api/review-queue/inject",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3)
        print(f"[dns] 📬 queued for Ollama:  {domain}", flush=True)
    except Exception as exc:
        print(f"[dns] ⚠️  inject failed   {domain}  ({exc})", file=sys.stderr, flush=True)


# ── DNS upstream forwarder ────────────────────────────────────

def _forward(query: bytes) -> bytes | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(UPSTREAM_TIMEOUT)
        s.sendto(query, (UPSTREAM_HOST, UPSTREAM_PORT))
        response, _ = s.recvfrom(4096)
        s.close()
        return response
    except Exception:
        return None


# ── Per-query handler (runs in its own thread) ────────────────

def _handle(query: bytes, addr: tuple, srv: socket.socket) -> None:
    try:
        if len(query) < 12:
            return

        domain, _ = _parse_name(query, 12)
        domain = domain.lower().rstrip(".")
        qtype  = _get_qtype(query)

        if not domain or "." not in domain:
            return

        # Skip noisy infra — forward without classifying
        if any(domain.endswith(s) for s in _SKIP_SUFFIXES):
            resp = _forward(query)
            if resp:
                srv.sendto(resp, addr)
            return

        # Strip www. for consistent lookup/blocking
        lookup = domain[4:] if domain.startswith("www.") else domain

        # ── 1. DB check (previously-decided domains) ────────────────
        blocked, blk_status = _is_blocked(lookup)
        if blocked:
            icon = "🛑" if blk_status == "permanent_block" else "⏸️ "
            print(f"[dns] {icon} BLOCKED({blk_status})  {lookup}", flush=True)
            srv.sendto(_block_response(query, qtype), addr)
            return

        # ── 2. Fast local check — seed list + keyword heuristics ─────
        #    Blocks on the VERY FIRST VISIT without waiting for Ollama
        should_block, new_status, category, risk = _fast_check(lookup)
        if should_block:
            _write_block(lookup, new_status, category, risk)
            icon = "🛑" if new_status == "permanent_block" else "⏸️ "
            print(f"[dns] {icon} AUTO-BLOCKED({new_status}) [{category} risk={risk:.2f}]  {lookup}", flush=True)
            srv.sendto(_block_response(query, qtype), addr)
            # Still queue for Ollama so it refines & shows in reviewer with rationale
            if qtype in (TYPE_A, TYPE_AAAA):
                threading.Thread(target=_inject, args=(lookup,), daemon=True).start()
            return

        # ── 3. Unknown domain — forward to upstream ───────────────────
        resp = _forward(query)
        if resp:
            srv.sendto(resp, addr)

        print(f"[dns] →  forwarded  {lookup}", flush=True)

        # Queue for Ollama classification (A/AAAA = actual browser navigation)
        if qtype in (TYPE_A, TYPE_AAAA):
            threading.Thread(target=_inject, args=(lookup,), daemon=True).start()

    except Exception as exc:
        print(f"[dns] error: {exc}", file=sys.stderr, flush=True)


# ── Entry point ───────────────────────────────────────────────

def main() -> None:
    if os.geteuid() != 0:
        print("ERROR: run_dns_proxy.py must run as root (needs port 53).", file=sys.stderr)
        print("  Run:  sudo .venv/bin/python3 run_dns_proxy.py", file=sys.stderr)
        sys.exit(1)

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        srv.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as exc:
        print(f"ERROR: Cannot bind {LISTEN_HOST}:{LISTEN_PORT} — {exc}", file=sys.stderr)
        print(
            "  Another service is using port 53. Stop it first:\n"
            "    sudo brew services stop dnsmasq",
            file=sys.stderr,
        )
        sys.exit(1)

    _vpn_tag = "(no VPN — using Google fallback)" if UPSTREAM_HOST == "8.8.8.8" else "(VPN detected ✓ — forwarding through your VPN)"
    print(f"✅ Guardian DNS proxy running on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"   Upstream DNS : {UPSTREAM_HOST}:{UPSTREAM_PORT}  {_vpn_tag}", flush=True)
    print(f"   Guardian API: {GUARDIAN_API}", flush=True)
    print(f"   DB: {DB_PATH}", flush=True)
    print(f"   Set Wi-Fi DNS:  networksetup -setdnsservers Wi-Fi 127.0.0.1", flush=True)
    print("", flush=True)

    try:
        while True:
            data, addr = srv.recvfrom(512)
            threading.Thread(
                target=_handle, args=(data, addr, srv), daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[dns proxy] stopped. Restore DNS: networksetup -setdnsservers Wi-Fi empty")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
