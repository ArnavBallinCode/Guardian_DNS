"""
DNS query sniffer — tails the dnsmasq log and feeds new domains
into the classifier queue for automatic risk assessment.

How it works:
  dnsmasq (with log-queries enabled) writes every DNS query to syslog
  or a dedicated log file. This module tails that log, extracts the
  queried domain from each line, deduplicates, and pushes unseen domains
  into an asyncio queue for the classifier worker to consume.

Log line format (dnsmasq):
  Mar  5 12:00:01 dnsmasq[1234]: query[A] example.com from 192.168.1.1
"""
from __future__ import annotations

import asyncio
import re
import subprocess
import sys
from pathlib import Path

# Queue consumed by classifier_worker.py
classify_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=500)

# Domains already seen this session — avoids re-classifying the same domain
# every time it's queried (browsers query a lot).
_seen: set[str] = set()

# Regex that matches dnsmasq query log lines for both A and AAAA record types
_QUERY_RE = re.compile(r"query\[(?:A|AAAA)\]\s+([\w.\-]+)\s+from")

# Internal / unroutable domains we should never waste LLM calls on
_SKIP_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".arpa",
    "localhost",
    ".apple.com.edgekey.net",
)

# Very frequent CDN / infrastructure domains that are noise
_SKIP_EXACT = {
    "apple.com", "icloud.com", "ocsp.apple.com", "mesu.apple.com",
    "time.apple.com", "mask.icloud.com", "appleid.apple.com",
    "gateway.icloud.com", "17.57.144.0",
}


def _should_skip(domain: str) -> bool:
    d = domain.lower()
    if d in _SKIP_EXACT:
        return True
    for suffix in _SKIP_SUFFIXES:
        if d.endswith(suffix):
            return True
    # Skip bare IP addresses
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
        return True
    # Skip entries without a dot (not real FQDNs)
    if "." not in d:
        return True
    return False


def _extract_domain(line: str) -> str | None:
    m = _QUERY_RE.search(line)
    if not m:
        return None
    domain = m.group(1).lower().rstrip(".")
    if _should_skip(domain):
        return None
    # Strip leading www. for deduplication purposes
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


async def _enqueue(domain: str) -> None:
    if domain in _seen:
        return
    _seen.add(domain)
    try:
        classify_queue.put_nowait(domain)
    except asyncio.QueueFull:
        pass  # Drop silently if queue is full — don't block the sniffer


# ── Log sources ───────────────────────────────────────────────

async def tail_log_file(path: str) -> None:
    """Tail a dnsmasq log file (when log-facility is set to a file)."""
    print(f"[dns_sniffer] tailing log file: {path}", flush=True)
    while True:
        try:
            with open(path, "r", errors="ignore") as f:
                f.seek(0, 2)  # seek to end — only read new lines
                while True:
                    line = f.readline()
                    if line:
                        domain = _extract_domain(line)
                        if domain:
                            await _enqueue(domain)
                    else:
                        await asyncio.sleep(0.05)
        except FileNotFoundError:
            # Log file disappeared (dnsmasq restarted) — wait and retry
            await asyncio.sleep(2)
        except Exception as exc:
            print(f"[dns_sniffer] log file error: {exc}", file=sys.stderr)
            await asyncio.sleep(2)


async def tail_syslog_macos() -> None:
    """
    On macOS, dnsmasq logs to syslog by default. We stream it via
    `log stream --predicate 'process == "dnsmasq"'` which is the
    macOS unified logging API — no file needed.
    """
    cmd = [
        "log", "stream",
        "--predicate", 'process == "dnsmasq"',
        "--style", "compact",
        "--level", "debug",
    ]
    print("[dns_sniffer] streaming macOS unified log for dnsmasq...", flush=True)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )

    assert proc.stdout is not None
    while True:
        line_bytes = await proc.stdout.readline()
        if not line_bytes:
            await asyncio.sleep(0.5)
            continue
        line = line_bytes.decode("utf-8", errors="ignore")
        domain = _extract_domain(line)
        if domain:
            await _enqueue(domain)


# Default log file written by dnsmasq when log-facility is set in upstream.conf
DNSMASQ_LOG_FILE = "/tmp/dnsmasq.log"


async def start(log_file: str | None = None) -> None:
    """
    Start the sniffer.
    - If log_file is given explicitly, tail that file.
    - Otherwise try DNSMASQ_LOG_FILE (/tmp/dnsmasq.log) — this is the most
      reliable method on macOS when dnsmasq runs as a root service.
    - Falls back to macOS unified log stream only if no file exists.
    """
    target = log_file or DNSMASQ_LOG_FILE

    import os
    # Wait up to 30s for the log file to appear (dnsmasq may still be starting)
    for _ in range(30):
        if os.path.exists(target):
            break
        print(f"[dns_sniffer] waiting for log file: {target}", flush=True)
        await asyncio.sleep(1)

    if os.path.exists(target):
        await tail_log_file(target)
    else:
        print(f"[dns_sniffer] log file not found after 30s, falling back to macOS log stream", flush=True)
        await tail_syslog_macos()
