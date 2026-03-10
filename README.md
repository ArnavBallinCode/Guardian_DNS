# Guardian DNS

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)](https://fastapi.tiangolo.com)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20llama3%3A8b-orange)](https://ollama.com)
[![Open Source](https://img.shields.io/badge/Open%20Source-%E2%9C%93-brightgreen)](LICENSE)

> **Privacy-first, AI-powered DNS safety filter for families — runs entirely on your local machine. Zero cloud. Zero telemetry. Zero compromise.**

Guardian DNS intercepts every DNS query on your device before it leaves the machine. A three-stage pipeline — seed blocklist → keyword heuristics → local LLM — decides in milliseconds whether a domain is safe. Reviewers and parents see a live console to audit, override, or whitelist in real time. All inference runs locally via [Ollama](https://ollama.com) (`llama3:8b`). No data ever leaves your network.

---

## Why Guardian DNS?

| Goal | How we achieve it |
|---|---|
| **Privacy by design** | DNS queries never leave the local machine; parent dashboard shows aggregate counts only — no browsing history |
| **Security by design** | 186-domain seed blocklist, 100+ keyword-regex heuristics, local LLM inference — no external API keys, no inbound attack surface |
| **Zero cloud dependency** | Ollama runs `llama3:8b` fully offline; SQLite for persistence; no third-party services |
| **Human + AI consensus** | Domains require both AI risk score ≥ 0.60 **and** community reviewer votes to reach `permanent_block` |
| **Deployable today** | Pure Python, 3 pip packages, one `sudo` command — works on any macOS/Linux machine in under 5 minutes |
| **Open source** | MIT licensed — fork it, extend it, ship it |

---

## How it works

```
You browse Chrome
     │
     ▼  DNS query: "reddit.com?"
Guardian DNS Proxy  (run_dns_proxy.py  •  UDP 127.0.0.1:53)
  ├─ DB check        → already decided? block or allow immediately
  ├─ Seed blocklist  → 186 known-harmful domains → BLOCK instantly
  ├─ Keyword rules   → 100+ regex patterns (adult/gambling/gore/piracy…) → BLOCK instantly
  └─ Unknown domain  → forward to 8.8.8.8, page loads
          │  POST /api/review-queue/inject  (background thread)
          ▼
Classifier Worker  (inside Guardian server)
  └─ Ollama LLM → contextual child-safety risk score (0.0 – 1.0)
          │
          ▼
domain_policy table  (SQLite: data/guardian.db)
  ├─ p_risk ≥ 0.60 → temporary_block  (BLOCKED + appears in reviewer queue)
  └─ p_risk < 0.60 → allow
          │  auto-poll every 2s
          ▼
Reviewer UI  (http://127.0.0.1:8000/ui/reviewer)
  ├─ Live queue — every browsed domain with AI risk badge
  ├─ 🛑 Block  → permanent_block instantly (DNS-blocked)
  └─ ✅ Allow  → whitelisted (never re-classified)
```

**Three classification signals (fastest to slowest):**
1. **Seed blocklist** — 186 curated known-harmful domains → blocked before any network traffic leaves
2. **Keyword heuristics** — regex patterns for adult, gambling, gore, piracy, phishing, drugs, extremism → blocked on first visit (no LLM)
3. **Ollama LLM** — any domain not caught above is forwarded + sent to `llama3:8b` for contextual analysis (~2–5s)

Blocked domains return `0.0.0.0` (A) or `::` (AAAA). The browser sees "This site can't be reached".

---

## Quick Start

Run each step in a **separate terminal tab** in order.

**Tab 1 — One-time setup (clone + install)**
```bash
git clone https://github.com/ArnavBallinCode/Guardian_DNS.git
cd Guardian_DNS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Tab 1 — Ollama (keep this running)**
```bash
ollama serve
# First time only — pull the model (3–5 GB download):
ollama pull llama3:8b
```

**Tab 2 — Guardian server (keep this running)**
```bash
cd Guardian_DNS
source .venv/bin/activate
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
# You should see: INFO: Uvicorn running on http://127.0.0.1:8000
```

**Tab 3 — Create accounts (run once, then never again)**
```bash
# Reviewer account
curl -s -X POST http://127.0.0.1:8000/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"username":"reviewer","password":"guardian123","role":"reviewer","display_name":"Reviewer"}'

# Parent account
curl -s -X POST http://127.0.0.1:8000/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"username":"parent","password":"guardian123","role":"parent","display_name":"Parent"}'
```

**Tab 3 — Open the UI**
```bash
open http://127.0.0.1:8000/ui/login
# Sign in with: reviewer / guardian123  (or parent / guardian123)
```

**Tab 4 — DNS proxy (needs sudo, keep this running)**
```bash
cd Guardian_DNS
sudo brew services stop dnsmasq    # only needed if dnsmasq is running
sudo .venv/bin/python3 run_dns_proxy.py
# You should see: ✅ Guardian DNS proxy running on 127.0.0.1:53
```

**Tab 5 — Point your Mac's Wi-Fi DNS at the proxy**
```bash
networksetup -setdnsservers Wi-Fi 127.0.0.1
# Verify blocking works:
dig +short pornhub.com @127.0.0.1     # → 0.0.0.0  (seed-blocked)
dig +short sexaddict.com @127.0.0.1   # → 0.0.0.0  (keyword-blocked)
dig +short google.com @127.0.0.1      # → real IP   (allowed)
```

**To stop everything**
```bash
# 1. Restore normal DNS first (do this before anything else)
networksetup -setdnsservers Wi-Fi empty

# 2. Ctrl-C in the DNS proxy tab

# 3. Ctrl-C in the server tab (or kill by port)
pkill -f "uvicorn app.main"
```

> **Tip — if you see "address already in use" on port 8000:**
> ```bash
> pkill -f "uvicorn app.main"
> sleep 1
> .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
> ```

---

## UI Pages

| Page | URL | Who uses it |
|---|---|---|
| Home | `http://127.0.0.1:8000/` | Anyone — overview |
| Reviewer Console | `http://127.0.0.1:8000/ui/reviewer` | Reviewers — live queue, assess, block/allow |
| Parent Dashboard | `http://127.0.0.1:8000/ui/parent` | Parents — block stats, add/remove domains |
| Setup Guide | `http://127.0.0.1:8000/ui/setup` | Anyone — step-by-step install |
| API Docs | `http://127.0.0.1:8000/docs` | Developers |

---

## Reviewer Live Queue

Open **Reviewer Console** → **"🔴 Needs Review"** tab. Polls every **2 seconds**. New domain rows flash blue on arrival.

| Action | Effect |
|---|---|
| 🛑 Block | Instantly `permanent_block` — DNS proxy starts blocking on next query |
| ✅ Allow | Whitelisted — never re-classified again |
| Click row → Assess | Re-run Ollama on that domain, see full AI rationale |
| Vote Approve/Reject | Community voting for nuanced decisions (3 votes + ≥70% confidence = permanent) |

---

## Confidence Policy

| Threshold | Value |
|---|---|
| Temporary block (keyword/AI) | `p_risk ≥ 0.60` |
| Permanent block (AI + votes) | `combined_confidence ≥ 0.70` |
| Minimum votes for auto-promote | 3 |
| AI weight in combined score | 0.40 |
| Vote weight in combined score | 0.60 |

---

## Key Files

| File | Purpose |
|---|---|
| `run_dns_proxy.py` | **Pure-Python DNS server** — the core of the system. No dnsmasq needed. |
| `app/main.py` | FastAPI server — all API routes + startup |
| `app/classifier_worker.py` | Async background worker — drains inject queue, calls Ollama |
| `app/engine.py` | Domain policy logic, vote tallying, seed pre-population |
| `app/blocklist.py` | Seed list (186 domains) + keyword heuristics (100+ patterns) |
| `app/llm.py` | Ollama integration — prompt, JSON parse, fallback |
| `data/guardian.db` | SQLite — `domain_policy`, `votes`, `blocked_events`, auth |
| `scripts/start_dns_proxy.sh` | Helper start script — stops dnsmasq, runs proxy, shows instructions |

---

## Security & Privacy Design Principles

- **No cloud calls** — all DNS resolution, LLM inference, and storage happen on `127.0.0.1`
- **No PII stored** — domain names only; no URLs, search terms, page content, or user identifiers
- **Aggregate-only parent view** — parents see category counts and aggregate block stats, never per-domain browsing history
- **No inbound ports** — Guardian listens only on loopback (`127.0.0.1:53` and `:8000`); not reachable from outside your machine
- **SQL parameterized queries** — all DB writes use SQLAlchemy / parameterized statements to prevent injection
- **JWT session tokens** — auth uses signed tokens; passwords are bcrypt-hashed at rest
- **Fail-open on LLM timeout** — if Ollama is unavailable, unknown domains are forwarded (not blocked), preventing false positives

---

## Project Structure

```
Guardian_DNS/
├── run_dns_proxy.py          # Pure-Python UDP DNS server (port 53)
├── app/
│   ├── main.py               # FastAPI app, routes, startup lifecycle
│   ├── classifier_worker.py  # Async queue worker — Ollama inference
│   ├── engine.py             # Domain policy logic, vote tallying
│   ├── blocklist.py          # 186 seed domains + 100+ keyword patterns
│   ├── llm.py                # Ollama client, prompt, JSON parser
│   ├── auth.py               # JWT + bcrypt auth
│   ├── db.py                 # SQLAlchemy + SQLite setup
│   ├── schemas.py            # Pydantic models
│   ├── settings.py           # Config (thresholds, ports, model name)
│   └── static/               # HTML/CSS/JS for all UI pages
├── scripts/
│   ├── apply_local_dns_filter.sh   # Point macOS DNS to 127.0.0.1
│   └── remove_local_dns_filter.sh  # Restore original DNS
├── docs/
│   ├── how-it-works.md       # Full architecture + demo flow
│   └── api-examples.md       # curl examples for every endpoint
├── data/guardian.db          # SQLite database (auto-created)
├── requirements.txt
└── LICENSE                   # MIT
```

---

## Full Documentation

- [How it works — full architecture & demo](docs/how-it-works.md)
- [API examples](docs/api-examples.md)
- [Demo guide](DEMO_GUIDE.md)

---

## Contributing

Guardian DNS is open source under the [MIT License](LICENSE). Contributions welcome.

```bash
git clone https://github.com/ArnavBallinCode/Guardian_DNS.git
cd Guardian_DNS
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Open issues, submit PRs, or fork and extend — the blocklist, heuristics, and LLM prompt are all designed to be swapped out.

---

## License

MIT © 2026 Arnav Angarkar — see [LICENSE](LICENSE) for full text.

