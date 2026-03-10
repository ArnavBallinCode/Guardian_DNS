"""
Classifier worker — drains the classify_queue populated by dns_sniffer.py
and runs each domain through the multi-signal assessment pipeline:

  Signal 1: seed blocklist  (instant, no LLM)
  Signal 2: keyword heuristics (instant, no LLM)
  Signal 3: Ollama LLM  (async, ~1-3s per domain)

Results are written directly to domain_policy (via engine.evaluate_domain),
making them immediately visible in the reviewer queue.

The worker is intentionally slow: it waits CLASSIFY_INTERVAL_S seconds
between LLM calls to avoid hammering Ollama and to batch-deduplicate.
Seed/heuristic hits are processed instantly and don't count towards rate limiting.
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime

from app.blocklist import assess_domain_multi_signal
from app.dns_sniffer import classify_queue
from app.engine import evaluate_domain, get_policy
from app.llm import assess_domain_with_ollama

# Seconds to wait between Ollama LLM calls (rate limit / battery saver)
CLASSIFY_INTERVAL_S = 2.0

# How many concurrent LLM calls to allow. Keep at 1 — Ollama is sequential.
MAX_CONCURRENT_LLM = 1

_llm_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LLM)


def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[classifier {ts}] {msg}", flush=True)


async def _classify_one(domain: str) -> None:
    """
    Run the full classification pipeline for a single domain.
    Skips domains that already have a policy (allow or block).
    """
    # Skip if already decided
    existing = get_policy(domain)
    if existing and existing["status"] in ("permanent_block", "allow"):
        return

    # Signal 1 + 2: seed blocklist and keyword heuristics (synchronous, fast)
    risk, category, source = assess_domain_multi_signal(domain)

    if source != "none":
        # Instant classification — no LLM needed
        decision = evaluate_domain(domain=domain, category=category, p_risk=risk)
        _log(f"[{source}] {domain} → {decision['action']} (risk={risk:.2f}, cat={category})")
        return

    # Signal 3: Ollama LLM (async, rate-limited)
    async with _llm_semaphore:
        try:
            loop = asyncio.get_event_loop()
            llm_result = await loop.run_in_executor(
                None,
                lambda: assess_domain_with_ollama(
                    domain=domain,
                    context="",
                    category_hint="unknown",
                ),
            )
            decision = evaluate_domain(
                domain=domain,
                category=llm_result.category,
                p_risk=llm_result.p_risk,
            )
            _log(
                f"[llm/{llm_result.model_used}] {domain} → "
                f"{decision['action']} (risk={llm_result.p_risk:.2f}, "
                f"cat={llm_result.category})"
            )
        except Exception as exc:
            _log(f"[llm error] {domain}: {exc}")
        finally:
            await asyncio.sleep(CLASSIFY_INTERVAL_S)


async def run_worker() -> None:
    """
    Continuously drain the classify_queue and classify each domain.
    Runs forever as an asyncio background task.
    """
    _log("classifier worker started")
    while True:
        try:
            domain = await asyncio.wait_for(classify_queue.get(), timeout=5.0)
        except asyncio.TimeoutError:
            continue

        asyncio.create_task(_classify_one(domain))
        classify_queue.task_done()
