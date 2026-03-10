# How Guardian DNS Works — End-to-End

## System Architecture

```
Browser / App
     │  DNS query: "sexaddict.com?"
     ▼
run_dns_proxy.py  (pure Python, UDP 127.0.0.1:53, needs sudo)
  ├── 1. DB check ──────────────── already in domain_policy?
  │       ├── permanent_block  →  0.0.0.0  (BLOCKED)
  │       ├── temporary_block  →  0.0.0.0  (BLOCKED, pending review)
  │       └── allow            →  forward to 8.8.8.8
  │
  ├── 2. Seed blocklist ────────── 186 curated known-harmful domains?
  │       └── YES  →  write permanent_block to DB  →  0.0.0.0  (BLOCKED)
  │
  ├── 3. Keyword heuristics ────── domain name matches bad pattern?
  │       └── risk ≥ 0.60  →  write temporary_block to DB  →  0.0.0.0  (BLOCKED)
  │
  └── 4. Unknown domain ──────────  forward to 8.8.8.8  →  page loads
          │  POST /api/review-queue/inject  (background thread, fire-and-forget)
          ▼
Guardian FastAPI Server  (app/main.py, http://127.0.0.1:8000)
  └── Classifier Worker  (app/classifier_worker.py  — async background task)
          ├── skip if already decided
          ├── seed blocklist / keyword check (again, in case missed)
          └── Ollama LLM  →  {p_risk, category, rationale}  (~2–5s)
                  │
                  ▼
          domain_policy table  (SQLite: data/guardian.db)
                  ├── p_risk ≥ 0.60  →  temporary_block  (proxy blocks on next DNS query)
                  └── p_risk < 0.60  →  allow

          │  Reviewer browser polls /api/review-queue every 2s
          ▼
Reviewer UI  (http://127.0.0.1:8000/ui/reviewer)
  ├── 🛑 Block button  →  POST /api/override  →  permanent_block  →  proxy blocks immediately
  └── ✅ Allow button  →  POST /api/override  →  allow  →  proxy allows forever
```

---

## Component Breakdown

### 1. Python DNS Proxy (`run_dns_proxy.py`)

**The core of the system.** Replaces dnsmasq entirely. No external dependencies — pure stdlib.

- Binds `127.0.0.1:53` as a UDP server (requires `sudo` for port 53)
- Every DNS query from the browser hits this first
- Spawns a thread per query — non-blocking, handles bursts
- **Three-stage decision per domain (< 2ms for stages 1–3):**
  1. Check `domain_policy` table in SQLite directly (no HTTP)
  2. Run `assess_domain_multi_signal()` — seed list + keyword regex
  3. If unknown, forward to `8.8.8.8` and fire background inject
- Returns `0.0.0.0` (A) or `::` (AAAA) for blocked domains
- Strips `www.` prefix for consistent lookup/blocking
- Skips infra/CDN noise (`.local`, `.arpa`, `.akamaiedge.net`, etc.)
- Session dedup — each domain only injected to Ollama once per process run

**Run:**
```bash
sudo .venv/bin/python3 run_dns_proxy.py
```

### 2. Guardian FastAPI Server (`app/main.py`)

Runs on `http://127.0.0.1:8000`. Starts two background asyncio tasks at startup:

1. **`run_worker()`** — drains the classifier queue, calls Ollama
2. **`pre_seed_blocklist()`** — `INSERT OR IGNORE` all 186 seed domains as `permanent_block` on every startup

Key API endpoints the proxy uses:
- `POST /api/review-queue/inject` — adds a domain to Ollama queue
- `GET /api/review-queue` — reviewer fetches live queue
- `POST /api/override` — reviewer/parent instantly force-sets a domain status

### 3. Classifier Worker (`app/classifier_worker.py`)

Async background task. Drains `classify_queue` (asyncio.Queue, max 500).

For each domain:
1. **Skip** if already `permanent_block` or `allow` in DB
2. **Seed blocklist** (`app/blocklist.py`) → instant `permanent_block`, p_risk=1.0
3. **Keyword heuristics** (`app/blocklist.py`) → if risk ≥ 0.60, instant decision
4. **Ollama LLM** (`app/llm.py`) → sends domain to local model, parses JSON response

Rate limit: 2s between LLM calls to avoid hammering Ollama.

### 4. Multi-Signal Blocklist (`app/blocklist.py`)

**Signal 1 — Seed Blocklist (186 domains):**
Curated list of known-harmful sites across 8 categories:
`adult-content`, `gambling`, `drugs-alcohol`, `violence-gore`, `self-harm`, `piracy`, `dating`, `dark-web-proxy`, `weapons`

All 186 are pre-loaded into `domain_policy` as `permanent_block` at every server startup via `pre_seed_blocklist()`. This ensures the proxy blocks them even before any Ollama inference.

**Signal 2 — Keyword Heuristics (100+ patterns):**
Regex patterns matched against domain name and TLD. Examples:
- `sex(?!t|pert|ton)` → adult-content, risk 0.70
- `casino` → gambling, risk 0.85
- `torrent` → piracy, risk 0.65
- `bestgore` → violence-gore, risk 0.95

Also checks risky TLDs: `.xxx`, `.adult`, `.porn`, `.bet`, `.casino`

> **Note:** An earlier `lstrip("https://")` bug silently broke keyword matching on domains
> starting with `s`, `h`, `t`, `p`, or `/` (e.g. `sexaddict.com` → `exaddict.com`).
> Fixed — scheme stripping now uses proper `startswith` checks.

### 5. SQLite Database (`data/guardian.db`)

**`domain_policy`** — one row per domain

| column | meaning |
|---|---|
| domain | normalized (lowercase, no www) |
| status | `allow` / `temporary_block` / `permanent_block` |
| category | `adult-content`, `gambling`, etc. |
| p_risk | AI risk score 0.0–1.0 |
| p_vote | community vote ratio 0.0–1.0 |
| combined_confidence | `0.4 * p_risk + 0.6 * p_vote` |
| review_required | 1 = needs human decision |
| updated_at | last write timestamp |

**`votes`** — reviewer votes (for community voting flow)

**`blocked_events`** — daily counts per category (for parent dashboard)

**`users` / `sessions`** — auth tables

### 6. Reviewer UI (`/ui/reviewer`)

**Live Review Queue tab** — polls `/api/review-queue` every **2 seconds**.

- New domain rows flash blue on first appearance
- "⚙️ Ollama classifying N domains…" row shown while LLM is working
- Domains sorted: `temporary_block` first (urgent, red), then by p_risk descending

**Quick actions per row (no assessment needed):**
- **🛑 Block** → `POST /api/override {action: "block"}` → immediately `permanent_block` → DNS proxy blocks on next query
- **✅ Allow** → `POST /api/override {action: "allow"}` → whitelisted

**Full assessment flow:**
1. Click domain row → auto-fills the Assess panel
2. Hit "⚡ Assess with Local AI" → runs Ollama, shows risk meter + rationale
3. Vote Approve/Reject (3 votes + combined confidence ≥ 70% = auto-promote to `permanent_block`)

### 7. Parent Dashboard (`/ui/parent`)

Parents see **aggregate statistics only** — no individual domain names or browsing history.
- Total blocks by category (last 7 days, chart)
- Add domain → immediately `permanent_block` (bypasses voting)
- Remove domain → deleted from `domain_policy`

### 8. Override API (`POST /api/override`)

Available to both `reviewer` and `parent` roles. Actions:
- `"block"` → `permanent_block`, risk=1.0
- `"allow"` → `allow`, risk=0.0
- `"temporary_block"` → `temporary_block`, risk=0.5
- `"remove"` → deletes row entirely

The DNS proxy picks up the change on the **next DNS query** for that domain (DB check takes < 1ms).

---

## Full Demo Flow

### Prerequisites
```bash
# Install Python deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Ollama
ollama serve          # keep running in its own tab
ollama pull llama3:8b
```

### Step 1 — Start Guardian server (Tab 1)
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
On startup you'll see:
```
[classifier HH:MM:SS] classifier worker started
INFO:     Uvicorn running on http://127.0.0.1:8000
```

### Step 2 — Start DNS proxy (Tab 2, needs sudo)
```bash
sudo brew services stop dnsmasq   # if running, free port 53
sudo .venv/bin/python3 run_dns_proxy.py
```
You'll see:
```
✅ Guardian DNS proxy running on 127.0.0.1:53
   Upstream: 8.8.8.8
   Set Wi-Fi DNS:  networksetup -setdnsservers Wi-Fi 127.0.0.1
```

### Step 3 — Point Mac DNS at the proxy (once per session)
```bash
networksetup -setdnsservers Wi-Fi 127.0.0.1

# Verify:
dig +short pornhub.com @127.0.0.1    # → 0.0.0.0 (blocked, seed list)
dig +short sexaddict.com @127.0.0.1  # → 0.0.0.0 (blocked, keyword)
dig +short google.com @127.0.0.1     # → real IP  (allowed)
```

### Step 4 — Open reviewer console
```bash
open http://127.0.0.1:8000/ui/reviewer
```
Sign in as a reviewer. Click the **"🔴 Needs Review"** tab.

### Step 5 — Browse the web

Open Chrome and visit a mix of sites. In the proxy terminal (Tab 2) you'll see:
```
[dns] 🛑 BLOCKED(permanent_block)  pornhub.com
[dns] ⏸️  BLOCKED(temporary_block)  sexaddict.com
[dns] →  forwarded  reddit.com
[dns] 📬 queued for Ollama:  reddit.com
```

In the Guardian server terminal (Tab 1):
```
[classifier 17:32:01] [keyword_heuristic] sexaddict.com → block (risk=0.70, cat=adult-content)
[classifier 17:32:04] [llm/llama3:8b] reddit.com → allow (risk=0.32, cat=social-media)
```

### Step 6 — Review in the UI

Within 2 seconds, browsed domains appear in the Reviewer queue with risk scores.
- Click **🛑 Block** to permanently block any domain instantly
- Click **✅ Allow** to whitelist it

### Step 7 — Restore DNS when done
```bash
networksetup -setdnsservers Wi-Fi empty
```

---

## Debugging

**Check what's in the DB:**
```bash
sqlite3 data/guardian.db \
  "SELECT domain, status, category, round(p_risk,2) as risk FROM domain_policy ORDER BY updated_at DESC LIMIT 20;"
```

**Check review queue via API:**
```bash
curl -s http://127.0.0.1:8000/api/review-queue | python3 -m json.tool | head -60
```

**Manually inject a domain (no DNS needed):**
```bash
curl -s -X POST http://127.0.0.1:8000/api/review-queue/inject \
  -H 'Content-Type: application/json' \
  -d '{"domain":"reddit.com"}'
```

**Check port 53 isn't held by dnsmasq:**
```bash
sudo lsof -i UDP:53 | grep -v mDNSResponder
# Should be empty (or show your python3 process once proxy is running)
```

**Test keyword detection directly:**
```bash
source .venv/bin/activate
python3 -c "
from app.blocklist import assess_domain_multi_signal
for d in ['sexaddict.com','casino-win.net','gore-videos.net','reddit.com']:
    risk, cat, src = assess_domain_multi_signal(d)
    print(f'{src:22s} risk={risk:.2f}  {d}')
"
```

**Check Ollama is reachable:**
```bash
curl -s http://127.0.0.1:11434/api/tags | python3 -m json.tool
# or
curl -s http://127.0.0.1:8000/api/health/ollama
```

**Proxy not starting — port 53 busy:**
```bash
sudo brew services stop dnsmasq
sudo pkill -f dnsmasq
sleep 1
sudo .venv/bin/python3 run_dns_proxy.py
```

---

## Why the Old dnsmasq Approach Was Replaced

| Problem | Root cause | New solution |
|---|---|---|
| dnsmasq couldn't bind port 53 | Ran as user LaunchAgent, not root | Python proxy runs under `sudo` directly |
| Log file `/tmp/dnsmasq.log` permission denied | Root-owned file, user-readable only | Proxy writes to DB directly, no log files |
| `log stream` unreliable for root dnsmasq | macOS unified log doesn't capture root-dnsmasq reliably | Proxy handles everything inline |
| Seed domains not blocked (sex.com etc.) | Export only read DB; seed list never loaded into DB | `pre_seed_blocklist()` at every startup |
| `sexaddict.com` slipped through | `lstrip("https://")` stripped chars from domain names | Fixed to proper `startswith` prefix removal |

---

## Security & Privacy Architecture

Guardian DNS is designed **privacy-first** and **security-by-design**:

| Property | Implementation |
|---|---|
| **No cloud calls** | All DNS queries, LLM inference, and storage stay on `127.0.0.1`. No external API keys. |
| **No PII stored** | Only domain names are recorded — no URLs, search queries, page content, or user identifiers |
| **Aggregate parent view** | Parent dashboard exposes category counts and block totals only — not per-domain browsing history |
| **Loopback-only binding** | Both the DNS proxy (`127.0.0.1:53`) and API server (`127.0.0.1:8000`) bind loopback only — not reachable from the network |
| **Parameterised SQL** | All DB writes go through SQLAlchemy ORM / parameterized statements — no raw SQL string concatenation |
| **bcrypt passwords** | User passwords are bcrypt-hashed before storage; never stored in plaintext |
| **Signed JWT sessions** | Session tokens are HMAC-signed; secret key is loaded from environment/config |
| **Fail-open LLM** | If Ollama is unreachable, unknown domains are forwarded (not blocked) — preventing false positives that would break the internet for the user |
| **Rate-limited LLM calls** | Classifier worker enforces a 2s gap between Ollama calls — prevents accidental resource exhaustion |

---

## Open Source

Guardian DNS is released under the [MIT License](../LICENSE).

```
MIT © 2026 Arnav Angarkar
https://github.com/ArnavBallinCode/Guardian_DNS
```

Fork it, extend the blocklist, swap in a different model, or deploy it on a Raspberry Pi as a home DNS resolver. The architecture is intentionally modular:

- **Swap the LLM** — change `MODEL_NAME` in `app/settings.py` to any Ollama-supported model
- **Extend the blocklist** — add domains to `SEED_BLOCKLIST` or regex patterns to `KEYWORD_RULES` in `app/blocklist.py`
- **Change thresholds** — `P_RISK_THRESHOLD`, `COMBINED_CONFIDENCE_THRESHOLD` in `app/settings.py`
- **Add upstream resolvers** — change `UPSTREAM_DNS` in `run_dns_proxy.py`
