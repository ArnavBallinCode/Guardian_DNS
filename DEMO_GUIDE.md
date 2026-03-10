# Guardian DNS — Demo Guide

> **Privacy-first, AI-powered DNS safety filter. Runs entirely locally. Works with ExpressVPN + Tunnelblick. MIT licensed.**
> Repository: https://github.com/ArnavBallinCode/Guardian_DNS

---

## Before the Demo — Start Everything

Run these once before you start showing anyone anything.

**Terminal 1 — Ollama:**
```bash
ollama serve
```

**Terminal 2 — Guardian server:**
```bash
cd Guardian_DNS
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 3 — DNS proxy (needs sudo):**
```bash
sudo .venv/bin/python3 run_dns_proxy.py
```
You'll see: `✅ Guardian DNS proxy running on 127.0.0.1:53`

**Terminal 4 — Activate DNS filtering:**
```bash
networksetup -setdnsservers Wi-Fi 127.0.0.1
```

**If using ExpressVPN + Tunnelblick** — run after VPN connects:
```bash
sudo bash scripts/restore_guardian_dns.sh
```

**Accounts (pre-created):**
- Reviewer → `http://127.0.0.1:8000/ui/login` → `reviewer / guardian123`
- Parent → `http://127.0.0.1:8000/ui/login` → `parent / guardian123`

---

## Demo Walkthrough (6 minutes)

### Scene 1 — The Big Picture (30 seconds)

Open a browser and go to `http://127.0.0.1:8000`.

**Say:** *"Guardian DNS sits between your browser and the internet. Every domain you visit hits this filter first. It blocks harmful sites instantly — no cloud, no API keys, everything runs on this laptop."*

Point out the dark/light toggle. Show the health indicator at the bottom confirming Ollama is running locally.

---

### Scene 2 — Instant Blocking — The Seed List (1 minute)

With DNS active, open a new browser tab and try to visit `pornhub.com`.

**What happens:** Browser shows "This site can't be reached" in under 1ms.

Back in Terminal 3 (proxy logs), point out:
```
[dns] 🛑 BLOCKED(permanent_block)  pornhub.com
```

**Say:** *"186 curated domains are blocked before any packet leaves this machine. No LLM needed. Sub-millisecond. The browser never even makes a TCP connection."*

---

### Scene 3 — Keyword Heuristics (30 seconds)

Try visiting `free-poker-slots.com` in the browser. It'll be blocked.

Proxy logs:
```
[dns] ⏸️  AUTO-BLOCKED(temporary_block) [gambling risk=0.85]  free-poker-slots.com
```

**Say:** *"100+ regex patterns catch gambling, adult, gore, phishing, and piracy domains by keyword — also without the LLM. First visit, instant block."*

---

### Scene 4 — AI Classification (2 minutes)

Log in at `http://127.0.0.1:8000/ui/login` as `reviewer / guardian123`.

You're now on the **Reviewer Console**.

1. In the **Assess Domain** box, type `tinder.com` → click **Assess with Local AI**
2. Wait ~10–15 seconds for Ollama
3. Show the result: risk score ~85%, category `dating`, full AI rationale
4. Click **🛑 Block** — permanent block applied instantly
5. Switch to a fresh browser tab, try `tinder.com` → blocked

**Say:** *"For anything not on the seed list or keyword list, Ollama runs a contextual analysis. Everything stays on-device — the model never phones home."*

---

### Scene 5 — Live Review Queue (1 minute)

Browse a few normal sites (`github.com`, `bbc.com`) — the proxy logs show them being forwarded and queued for Ollama in the background.

Back in the Reviewer Console, click the **🔴 Needs Review** tab.

New domain rows flash in every 2 seconds showing AI risk scores.

**Say:** *"Every domain you browse automatically enters the review queue. A reviewer sees the AI's verdict and can override it — one click to permanently block or whitelist."*

---

### Scene 6 — Parent Dashboard (1 minute)

Log out, log in as `parent / guardian123` → `http://127.0.0.1:8000/ui/parent`.

Show:
- Total blocked count
- Category breakdown (adult / gambling / piracy / etc.)
- Blocked domains table with risk scores
- **Parent can add/remove domains directly** without needing a reviewer

**Say:** *"Parents get the aggregate view — they see categories and counts, not individual browsing history. Privacy by design. They can also instantly block or unblock specific domains themselves."*

---

### Scene 7 — VPN Integration (30 seconds)

**Say:** *"This works alongside ExpressVPN. Guardian filters DNS first, then forwards through your VPN's DNS server — blocking still works, VPN encryption still works, nothing breaks."*

Show the single fix script needed after Tunnelblick overrides DNS:
```bash
sudo bash scripts/restore_guardian_dns.sh
# Output: [guardian] DNS for Wi-Fi is now: 127.0.0.1
# Flow: Browser → Guardian (127.0.0.1:53) → ExpressVPN DNS → Internet
```

---

## Stop Everything

**DNS first — always — or you'll lose internet:**
```bash
networksetup -setdnsservers Wi-Fi empty
# Then Ctrl-C in proxy terminal
pkill -f 'uvicorn app.main'
```

---

## Key Talking Points

| Point | One-liner |
|---|---|
| **No cloud** | Everything runs on `127.0.0.1` — no API keys, no telemetry, air-gap capable |
| **Three-stage filter** | Seed list (<1ms) → keyword regex (<1ms) → Ollama LLM (~10s) |
| **VPN compatible** | Works with ExpressVPN + Tunnelblick/OpenVPN — Guardian + VPN, not either/or |
| **Privacy by design** | Parents see category counts only — no URLs, no search history, no per-user tracking |
| **AI + human** | AI risk ≥ 0.60 AND reviewer vote = permanent block. No single point of authority |
| **Open source** | MIT licensed — swap the model, extend the blocklist, deploy anywhere |
| **5-minute deploy** | 3 pip packages, one `sudo` command, no accounts, no sign-up |

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/decision/assess` | POST | Reviewer | Run Ollama assessment on a domain |
| `/decision/vote` | POST | Reviewer | Vote on an AI judgment |
| `/api/override` | POST | Reviewer/Parent | Instant block or allow |
| `/api/parent/stats` | GET | Parent | Blocked counts by category |
| `/api/parent/blocklist` | GET | Parent | Full blocked domain list |
| `/api/review-queue` | GET | Reviewer | Live unreviewed domain queue |
| `/api/health/ollama` | GET | None | Confirm local AI is running |
| `/export/domains.txt` | GET | None | Export blocklist for dnsmasq |
| `/docs` | GET | None | FastAPI Swagger UI |

---

## Architecture (One Diagram)

```
Browser
  │  DNS query
  ▼
Guardian DNS Proxy  127.0.0.1:53
  ├─ Seed blocklist (186 domains)  ──→  0.0.0.0  BLOCKED
  ├─ Keyword heuristics (100+ regex) ─→  0.0.0.0  BLOCKED
  └─ Unknown → forward to 8.8.8.8
                   │  (background)
                   ▼
             Ollama LLM (local)
                   │
                   ▼
             SQLite domain_policy
                   │
          ┌────────┴────────┐
          ▼                 ▼
    Reviewer UI        Parent Dashboard
    (block/allow)      (stats + add/remove)
```
