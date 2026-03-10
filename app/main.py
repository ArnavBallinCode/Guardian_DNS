from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.auth import _init_auth_tables, get_session_user, require_auth, signin, signout, signup
from app.blocklist import assess_domain_multi_signal
from app.classifier_worker import run_worker
from app.context_fetcher import build_domain_context
from app.db import initialize_db, get_conn
from app.dns_sniffer import classify_queue
from app.engine import (
    evaluate_domain,
    export_permanent_block_domains,
    get_parent_summary,
    pre_seed_blocklist,
    submit_vote,
)
from app.llm import assess_domain_with_ollama
from app.schemas import (
    AssessRequest,
    AssessResponse,
    AuthUserResponse,
    EvaluateRequest,
    EvaluateResponse,
    ParentBlockRequest,
    ParentSummaryResponse,
    SetupActionRequest,
    SetupActionResponse,
    SigninRequest,
    SigninResponse,
    SignupRequest,
    VoteRequest,
    VoteResponse,
)

app = FastAPI(title="Guardian DNS MVP", version="0.3.0")
STATIC_DIR = Path(__file__).parent / "static"
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── Helpers ───────────────────────────────────────────────────

async def _run_script_async(command: list[str]) -> SetupActionResponse:
    """Run a shell script without blocking the event loop."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
        return SetupActionResponse(
            success=proc.returncode == 0,
            exit_code=proc.returncode or 0,
            stdout=(stdout.decode("utf-8", errors="ignore"))[-6000:],
            stderr=(stderr.decode("utf-8", errors="ignore"))[-6000:],
        )
    except asyncio.TimeoutError:
        return SetupActionResponse(
            success=False,
            exit_code=-1,
            stdout="",
            stderr="Script timed out after 180 seconds",
        )


def _get_token(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return request.cookies.get("guardian_token")


# ── Startup ───────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    initialize_db()
    _init_auth_tables()
    # Pre-populate seed blocklist so DNS proxy blocks known domains immediately
    pre_seed_blocklist()
    # Start background classifier that processes domains injected by the DNS proxy
    asyncio.create_task(run_worker())


# ── Home ──────────────────────────────────────────────────────

@app.get("/")
def home_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "home.html")


# ── Health ────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/health/ollama")
def ollama_health() -> dict:
    """Check if Ollama is reachable and list available models."""
    from app.settings import settings
    try:
        req = urllib.request.Request(
            url=f"{settings.ollama_base_url}/api/tags",
            headers={"Content-Type": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read().decode("utf-8", errors="ignore")
        data = json.loads(raw)
        models = [m.get("name", "unknown") for m in (data.get("models") or [])]
        return {"ok": True, "models": models}
    except Exception:
        return {"ok": False, "models": []}


@app.get("/api/recent-assessments")
def recent_assessments(limit: int = Query(default=10, ge=1, le=50)) -> list:
    """Return the most recent domain policy entries."""
    from app.db import get_conn
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT domain, status, category, p_risk, p_vote, combined_confidence, review_required, updated_at "
            "FROM domain_policy ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "domain": r["domain"],
            "status": r["status"],
            "category": r["category"],
            "p_risk": r["p_risk"],
            "p_vote": r["p_vote"],
            "combined_confidence": r["combined_confidence"],
            "review_required": bool(r["review_required"]),
            "updated_at": r["updated_at"],
        }
        for r in rows
    ]


@app.get("/api/review-queue")
def review_queue(limit: int = Query(default=50, ge=1, le=200)) -> dict:
    """
    Domains that have been auto-classified by the DNS sniffer and need
    a human reviewer decision. Returns temporary_block entries first
    (highest urgency), then unseen domains sorted by risk score desc.
    Also shows the live classifier queue size.
    """
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT domain, status, category, p_risk, p_vote, review_required, updated_at
            FROM domain_policy
            ORDER BY
                CASE status
                    WHEN 'temporary_block' THEN 0
                    WHEN 'allow' THEN 1
                    ELSE 2
                END,
                p_risk DESC,
                updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {
        "pending_classify": classify_queue.qsize(),
        "items": [
            {
                "domain": r["domain"],
                "status": r["status"],
                "category": r["category"],
                "p_risk": r["p_risk"],
                "p_vote": r["p_vote"],
                "review_required": bool(r["review_required"]),
                "updated_at": r["updated_at"],
            }
            for r in rows
        ],
    }


@app.post("/api/review-queue/inject")
def inject_domain(request: Request, payload: dict) -> dict:
    """
    Manually inject a domain into the classifier queue (for testing
    without real DNS traffic). Does not require auth so the setup
    page can use it for demo purposes.
    """
    domain = str(payload.get("domain", "")).strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="invalid_domain")
    try:
        classify_queue.put_nowait(domain)
    except Exception:
        raise HTTPException(status_code=429, detail="queue_full")
    return {"status": "queued", "domain": domain, "queue_size": classify_queue.qsize()}


@app.post("/api/override")
def override_domain(request: Request, payload: dict) -> dict:
    """
    Instantly force a domain to a specific status — bypasses voting.
    Allowed by: reviewer (block/temporary_block/allow) and parent (block/allow).
    action: "block" | "allow" | "temporary_block" | "remove"
    """
    from app.engine import upsert_policy, normalize_domain
    from app.db import get_conn as _gc

    user = require_auth(request)
    role = user.get("role", "")
    if role not in ("reviewer", "parent"):
        raise HTTPException(status_code=403, detail="forbidden")

    domain = str(payload.get("domain", "")).strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="invalid_domain")
    domain = normalize_domain(domain)

    action = str(payload.get("action", "")).strip()
    if action not in ("block", "allow", "temporary_block", "remove"):
        raise HTTPException(status_code=400, detail="invalid_action")

    if action == "remove":
        with _gc() as conn:
            conn.execute("DELETE FROM domain_policy WHERE domain = ?", (domain,))
        return {"status": "removed", "domain": domain}

    status_map = {"block": "permanent_block", "allow": "allow", "temporary_block": "temporary_block"}
    new_status = status_map[action]
    category = str(payload.get("category", "manual-override")).strip() or "manual-override"

    upsert_policy(
        domain=domain,
        status=new_status,
        category=category,
        p_risk=1.0 if new_status == "permanent_block" else (0.5 if new_status == "temporary_block" else 0.0),
        p_vote=1.0 if new_status == "permanent_block" else None,
        combined_confidence=1.0 if new_status == "permanent_block" else None,
        review_required=(new_status == "temporary_block"),
    )
    return {"status": new_status, "domain": domain, "set_by": user.get("username")}


# ── Auth endpoints ────────────────────────────────────────────

@app.post("/auth/signup", response_model=AuthUserResponse)
def auth_signup(payload: SignupRequest) -> AuthUserResponse:
    try:
        user = signup(
            username=payload.username,
            password=payload.password,
            role=payload.role,
            display_name=payload.display_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AuthUserResponse(**user)


@app.post("/auth/signin", response_model=SigninResponse)
def auth_signin(payload: SigninRequest, response: Response) -> SigninResponse:
    try:
        result = signin(payload.username, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    response.set_cookie(
        key="guardian_token",
        value=result["token"],
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600,
        path="/",
    )
    return SigninResponse(
        token=result["token"],
        user=AuthUserResponse(**result["user"]),
    )


@app.post("/auth/signout")
def auth_signout(request: Request, response: Response) -> dict:
    token = _get_token(request)
    if token:
        signout(token)
    response.delete_cookie("guardian_token", path="/")
    return {"status": "signed_out"}


@app.get("/auth/me")
def auth_me(request: Request) -> dict:
    user = require_auth(request)
    return user


# ── UI pages ──────────────────────────────────────────────────

@app.get("/ui/login")
def login_ui() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/ui/reviewer", response_model=None)
def reviewer_ui(request: Request):
    token = _get_token(request)
    user = get_session_user(token) if token else None
    if not user or user["role"] != "reviewer":
        return RedirectResponse("/ui/login?next=/ui/reviewer&role=reviewer")
    return FileResponse(STATIC_DIR / "reviewer.html")


@app.get("/ui/parent", response_model=None)
def parent_ui(request: Request):
    token = _get_token(request)
    user = get_session_user(token) if token else None
    if not user or user["role"] != "parent":
        return RedirectResponse("/ui/login?next=/ui/parent&role=parent")
    return FileResponse(STATIC_DIR / "parent.html")


@app.get("/ui/setup", response_model=None)
def setup_ui(request: Request):
    token = _get_token(request)
    user = get_session_user(token) if token else None
    if not user:
        return RedirectResponse("/ui/login?next=/ui/setup")
    return FileResponse(STATIC_DIR / "setup.html")


# ── Setup: downloads ──────────────────────────────────────────

@app.get("/setup/download/apply", response_class=FileResponse)
def download_apply_script() -> FileResponse:
    return FileResponse(
        path=SCRIPTS_DIR / "apply_local_dns_filter.sh",
        filename="apply_local_dns_filter.sh",
        media_type="text/x-shellscript",
    )


@app.get("/setup/download/remove", response_class=FileResponse)
def download_remove_script() -> FileResponse:
    return FileResponse(
        path=SCRIPTS_DIR / "remove_local_dns_filter.sh",
        filename="remove_local_dns_filter.sh",
        media_type="text/x-shellscript",
    )


# ── Setup: one-click (async, auth-protected) ─────────────────

@app.post("/setup/run/apply", response_model=SetupActionResponse)
async def run_apply_setup(payload: SetupActionRequest, request: Request) -> SetupActionResponse:
    require_auth(request)
    script = str(SCRIPTS_DIR / "apply_local_dns_filter.sh")
    return await _run_script_async(["/bin/bash", script, payload.service_name, payload.api_url])


@app.post("/setup/run/remove", response_model=SetupActionResponse)
async def run_remove_setup(payload: SetupActionRequest, request: Request) -> SetupActionResponse:
    require_auth(request)
    script = str(SCRIPTS_DIR / "remove_local_dns_filter.sh")
    return await _run_script_async(["/bin/bash", script, payload.service_name])


# ── Domain assessment (reviewer only) ────────────────────────

@app.post("/decision/evaluate", response_model=EvaluateResponse)
def decision_evaluate(payload: EvaluateRequest, request: Request) -> EvaluateResponse:
    require_auth(request, required_role="reviewer")
    result = evaluate_domain(payload.domain, payload.category, payload.p_risk)
    return EvaluateResponse(**result)


@app.post("/decision/assess", response_model=AssessResponse)
def decision_assess(payload: AssessRequest, request: Request) -> AssessResponse:
    require_auth(request, required_role="reviewer")

    # ── Multi-signal check first — skip LLM for heuristics ──
    risk, category, source = assess_domain_multi_signal(payload.domain)
    
    if source != "none":
        decision = evaluate_domain(
            domain=payload.domain,
            category=category,
            p_risk=risk,
        )
        msg = "Domain is on the curated seed blocklist." if source == "seed_blocklist" else f"Domain flagged by keyword heuristics ({category})."
        return AssessResponse(
            domain=payload.domain,
            p_risk=risk,
            llm_category=category,
            llm_rationale=f"{msg} No LLM assessment needed.",
            model_used=source,
            action=decision["action"],
            reason=decision["reason"],
            bypassable=decision["bypassable"],
            review_required=decision["review_required"],
            combined_confidence=decision["combined_confidence"],
        )

    context = "" if payload.skip_context_fetch else build_domain_context(payload.domain, payload.evidence_urls)
    try:
        llm_result = assess_domain_with_ollama(
            domain=payload.domain,
            context=context,
            category_hint=payload.category_hint,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    decision = evaluate_domain(
        domain=payload.domain,
        category=llm_result.category,
        p_risk=llm_result.p_risk,
    )

    return AssessResponse(
        domain=payload.domain,
        p_risk=llm_result.p_risk,
        llm_category=llm_result.category,
        llm_rationale=llm_result.rationale,
        model_used=llm_result.model_used,
        action=decision["action"],
        reason=decision["reason"],
        bypassable=decision["bypassable"],
        review_required=decision["review_required"],
        combined_confidence=decision["combined_confidence"],
    )


# ── Voting (reviewer only) ───────────────────────────────────

@app.post("/review/vote", response_model=VoteResponse)
@app.post("/decision/vote", response_model=VoteResponse, include_in_schema=False)
def review_vote(payload: VoteRequest, request: Request) -> VoteResponse:
    require_auth(request, required_role="reviewer")
    if not payload.proof.strip():
        raise HTTPException(status_code=400, detail="proof_required")

    try:
        result = submit_vote(payload.domain, payload.reviewer_id, payload.agree)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return VoteResponse(**result)


# ── Parent dashboard (parent only) ───────────────────────────

@app.get("/parent/summary", response_model=ParentSummaryResponse)
@app.get("/api/parent/stats", response_model=ParentSummaryResponse, include_in_schema=False)
def parent_summary(request: Request, days: int = Query(default=7, ge=1, le=90)) -> ParentSummaryResponse:
    require_auth(request, required_role="parent")
    return ParentSummaryResponse(**get_parent_summary(days=days))


@app.get("/api/parent/blocklist")
def parent_blocklist(request: Request):
    """Return the list of blocked domains visible to the parent."""
    require_auth(request, required_role="parent")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT domain, status, category, p_risk, updated_at FROM domain_policy WHERE status IN ('permanent_block', 'temporary_block') ORDER BY updated_at DESC"
        ).fetchall()
        return [
            {
                "domain": dict(row)["domain"],
                "status": dict(row)["status"],
                "category": dict(row)["category"],
                "risk_score": dict(row)["p_risk"],
                "updated_at": dict(row)["updated_at"],
            }
            for row in rows
        ]


@app.post("/api/parent/blocklist")
def add_parent_block(payload: ParentBlockRequest, request: Request):
    """Parent manually adds a domain to the blocklist."""
    require_auth(request, required_role="parent")
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO domain_policy (domain, status, category, p_risk, p_vote, combined_confidence, review_required)
            VALUES (?, 'permanent_block', ?, 1.0, 1.0, 1.0, 0)
            ON CONFLICT(domain) DO UPDATE SET
                status = 'permanent_block',
                category = excluded.category,
                p_risk = 1.0,
                combined_confidence = 1.0,
                updated_at = CURRENT_TIMESTAMP
            """,
            (payload.domain.strip().lower(), payload.category)
        )
    return {"status": "ok", "domain": payload.domain, "action": "added"}


@app.delete("/api/parent/blocklist/{domain:path}")
def remove_parent_block(domain: str, request: Request):
    """Parent manually removes a domain from the blocklist."""
    require_auth(request, required_role="parent")
    with get_conn() as conn:
        conn.execute("DELETE FROM domain_policy WHERE domain = ?", (domain.strip().lower(),))
    return {"status": "ok", "domain": domain, "action": "removed"}


# ── Exports (public — used by dnsmasq script) ────────────────

@app.get("/export/domains.txt", response_class=PlainTextResponse)
def export_domains_txt() -> str:
    domains = export_permanent_block_domains()
    return "\n".join(domains)


@app.get("/export/rpz", response_class=PlainTextResponse)
def export_rpz() -> str:
    domains = export_permanent_block_domains()
    lines = ["$TTL 60", "@ SOA localhost. root.localhost. 1 3600 900 604800 60", "@ NS localhost."]
    lines.extend([f"{domain} CNAME ." for domain in domains])
    return "\n".join(lines)
