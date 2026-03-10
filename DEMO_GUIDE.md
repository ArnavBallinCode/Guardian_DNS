# Guardian DNS — Demo Guide

> **Privacy-first, AI-powered DNS safety filter. Runs entirely locally. Zero cloud. MIT licensed.**
> Repository: https://github.com/ArnavBallinCode/Guardian_DNS

## Quick Start

```bash
# Terminal 1: Start Ollama (if not running)
ollama serve

# Terminal 2: Start the application
git clone https://github.com/ArnavBallinCode/Guardian_DNS.git
cd Guardian_DNS
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** in your browser.

## Demo Walkthrough (5 minutes)

### Step 1: Landing Page
- Show the landing page with animated hero and Ollama status
- Toggle dark/light mode with the ☀️/🌙 button
- Point out "Local AI active: llama3:8b" at the bottom

### Step 2: Sign Up as Reviewer
- Click **Sign In** → **Sign Up** tab
- Username: `demo_reviewer`, Password: `demo1234`, Role: **Reviewer**
- You'll be redirected to the **Reviewer Console**

### Step 3: Assess a Seed-Blocked Domain
- Type `pornhub.com` in the Domain field
- Enable **Fast mode** checkbox
- Click **⚡ Assess with Local AI**
- **Instant result** — no LLM wait:
  - Risk: **100% — Critical Risk** 🚨
  - Model: `seed_blocklist`
  - Reason: "Domain is on the curated seed blocklist"
- Toggle **{ } JSON** to show the raw API response

### Step 4: Assess an LLM-Scored Domain
- Type `tinder.com`, click Assess
- Wait ~15 seconds for the LLM
- **Result**: ~85% risk, category: `dating`
- Show the human-readable explanation with risk meter bar

### Step 5: Vote on AI Judgment
- In the **Adult Vote** section, enter a rationale: "Confirmed adult dating platform"
- Click **✅ Approve AI Judgment**
- Show the vote result with combined confidence

### Step 6: Switch to Parent Dashboard
- Click **Sign Out**
- Sign up as: `demo_parent`, Password: `demo1234`, Role: **Parent**
- Show the **Parent Dashboard** with:
  - Total blocked count
  - Category breakdown bar chart
  - **Blocked Domains table** with risk scores
  - **Privacy explainer** — parents see domains, not search history

### Step 7: DNS Integration (Optional)
```bash
# On Laptop 1 (server):
bash scripts/apply_local_dns_filter.sh "Wi-Fi"

# On Laptop 2 (client):
# Set DNS to Laptop 1's IP in System Preferences > Network > Wi-Fi > DNS

# To remove:
bash scripts/remove_local_dns_filter.sh "Wi-Fi"
```

## Key Talking Points

1. **No cloud dependency** — everything runs locally on `127.0.0.1`; no API keys, no telemetry, works air-gapped
2. **Privacy by design** — parents see aggregate category counts only — no browsing history, no URLs, no per-user tracking
3. **Security by design** — bcrypt passwords, signed JWTs, parameterized SQL, loopback-only binding
4. **AI + Human consensus** — a domain needs AI risk ≥ 0.60 **and** reviewer votes to become permanently blocked; no single point of authority
5. **Three-stage filter (fastest to slowest)** — seed blocklist (186 domains, <1ms) → keyword regex (100+ patterns, <1ms) → local Ollama LLM (~2–5s)
6. **Open source, MIT licensed** — fully auditable; swap the model, extend the blocklist, deploy anywhere
7. **Deployable in < 5 minutes** — 3 pip packages, one `sudo` command, no external accounts

## API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/decision/assess` | POST | Reviewer | Run AI assessment on a domain |
| `/decision/vote` | POST | Reviewer | Vote on an AI judgment |
| `/api/parent/stats` | GET | Parent | Get blocked counts by category |
| `/api/parent/blocklist` | GET | Parent | Get list of blocked domains |
| `/api/health/ollama` | GET | None | Check if local AI is running |
| `/api/recent-assessments` | GET | None | Get recent assessment feed |
| `/export/domains.txt` | GET | None | Export blocked domains for dnsmasq |
| `/docs` | GET | None | FastAPI Swagger UI |

## Architecture

```
Browser ──→ FastAPI App ──→ Seed Blocklist Check
                │                    ↓ (if not in list)
                │              Ollama LLM (local)
                │                    ↓
                │              Domain Policy DB (SQLite)
                │                    ↓
                └──→ Reviewer votes ──→ Combined confidence
                            ↓
              dnsmasq picks up blocked domains ──→ DNS filtering
```
