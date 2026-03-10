from __future__ import annotations
from datetime import date

from app.blocklist import check_seed_blocklist, SEED_LOOKUP
from app.db import get_conn
from app.settings import settings


def pre_seed_blocklist() -> None:
    """
    Pre-populate domain_policy with every domain from the curated seed blocklist
    as permanent_block so they are blocked by the DNS proxy immediately on first
    run, without needing a reviewer to assess them first.
    Uses INSERT OR IGNORE so existing reviewer decisions are never overwritten.
    """
    with get_conn() as conn:
        for domain, category in SEED_LOOKUP.items():
            conn.execute(
                """
                INSERT OR IGNORE INTO domain_policy
                (domain, status, category, p_risk, p_vote, combined_confidence, review_required)
                VALUES (?, 'permanent_block', ?, 1.0, 1.0, 1.0, 0)
                """,
                (domain, category),
            )


def normalize_domain(domain: str) -> str:
    return domain.strip().lower()


def get_policy(domain: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM domain_policy WHERE domain = ?", (normalize_domain(domain),)
        ).fetchone()
    return row


def upsert_policy(
    domain: str,
    status: str,
    category: str,
    p_risk: float | None,
    p_vote: float | None,
    combined_confidence: float | None,
    review_required: bool,
) -> None:
    domain = normalize_domain(domain)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO domain_policy(domain, status, category, p_risk, p_vote, combined_confidence, review_required)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                status=excluded.status,
                category=excluded.category,
                p_risk=excluded.p_risk,
                p_vote=excluded.p_vote,
                combined_confidence=excluded.combined_confidence,
                review_required=excluded.review_required,
                updated_at=CURRENT_TIMESTAMP
            """,
            (domain, status, category, p_risk, p_vote, combined_confidence, 1 if review_required else 0),
        )


def add_blocked_event(category: str) -> None:
    day = str(date.today())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO blocked_events(day, category, blocked_count)
            VALUES(?, ?, 1)
            ON CONFLICT(day, category) DO UPDATE SET
                blocked_count = blocked_count + 1
            """,
            (day, category),
        )


def evaluate_domain(domain: str, category: str, p_risk: float) -> dict:
    domain = normalize_domain(domain)

    # ── Seed blocklist: instant permanent block ──
    is_seed_blocked, seed_category = check_seed_blocklist(domain)
    if is_seed_blocked:
        effective_category = seed_category or category
        upsert_policy(
            domain=domain,
            status="permanent_block",
            category=effective_category,
            p_risk=1.0,
            p_vote=1.0,
            combined_confidence=1.0,
            review_required=False,
        )
        add_blocked_event(effective_category)
        return {
            "domain": domain,
            "action": "block",
            "reason": "seed_blocklist",
            "bypassable": False,
            "review_required": False,
            "combined_confidence": 1.0,
        }

    policy = get_policy(domain)

    if policy and policy["status"] == "allow":
        return {
            "domain": domain,
            "action": "allow",
            "reason": "listed_allow",
            "bypassable": False,
            "review_required": False,
            "combined_confidence": policy["combined_confidence"],
        }

    if policy and policy["status"] == "permanent_block":
        add_blocked_event(policy["category"])
        return {
            "domain": domain,
            "action": "block",
            "reason": "listed_permanent_block",
            "bypassable": False,
            "review_required": False,
            "combined_confidence": policy["combined_confidence"],
        }

    if p_risk >= settings.temp_threshold:
        upsert_policy(
            domain=domain,
            status="temporary_block",
            category=category,
            p_risk=p_risk,
            p_vote=None,
            combined_confidence=None,
            review_required=True,
        )
        add_blocked_event(category)
        return {
            "domain": domain,
            "action": "temporary_block",
            "reason": "high_llm_risk",
            "bypassable": True,
            "review_required": True,
            "combined_confidence": None,
        }

    upsert_policy(
        domain=domain,
        status="allow",
        category=category,
        p_risk=p_risk,
        p_vote=None,
        combined_confidence=None,
        review_required=False,
    )
    return {
        "domain": domain,
        "action": "allow",
        "reason": "below_temporary_threshold",
        "bypassable": False,
        "review_required": False,
        "combined_confidence": None,
    }


def submit_vote(domain: str, reviewer_id: str, agree: bool) -> dict:
    domain = normalize_domain(domain)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO votes(domain, reviewer_id, agree)
            VALUES(?, ?, ?)
            ON CONFLICT(domain, reviewer_id) DO UPDATE SET agree=excluded.agree
            """,
            (domain, reviewer_id, 1 if agree else 0),
        )
        vote_rows = conn.execute(
            "SELECT agree FROM votes WHERE domain = ?", (domain,)
        ).fetchall()
        policy = conn.execute(
            "SELECT * FROM domain_policy WHERE domain = ?", (domain,)
        ).fetchone()

    if not policy:
        raise ValueError("domain_not_found_in_policy")

    votes = len(vote_rows)
    agree_count = sum(row["agree"] for row in vote_rows)
    p_vote = agree_count / votes if votes else 0.0
    p_risk = float(policy["p_risk"] or 0.0)
    combined = settings.ai_weight * p_risk + settings.vote_weight * p_vote

    permanently_blocked = votes >= settings.min_votes and combined >= settings.permanent_threshold

    upsert_policy(
        domain=domain,
        status="permanent_block" if permanently_blocked else "temporary_block",
        category=policy["category"],
        p_risk=p_risk,
        p_vote=p_vote,
        combined_confidence=combined,
        review_required=not permanently_blocked,
    )

    return {
        "domain": domain,
        "votes": votes,
        "p_vote": round(p_vote, 4),
        "p_risk": round(p_risk, 4),
        "combined_confidence": round(combined, 4),
        "permanently_blocked": permanently_blocked,
    }


def get_parent_summary(days: int = 7) -> dict:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT category, SUM(blocked_count) AS total
            FROM blocked_events
            WHERE day >= date('now', ?)
            GROUP BY category
            ORDER BY total DESC
            """,
            (f"-{days} day",),
        ).fetchall()

    by_category = {row["category"]: int(row["total"]) for row in rows}
    return {
        "total_blocked": sum(by_category.values()),
        "by_category": by_category,
    }


def export_permanent_block_domains() -> list[str]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT domain FROM domain_policy WHERE status = 'permanent_block' ORDER BY domain"
        ).fetchall()
    return [row["domain"] for row in rows]
