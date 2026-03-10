from __future__ import annotations
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from app.settings import settings


@dataclass
class LLMAssessment:
    p_risk: float
    category: str
    rationale: str
    model_used: str


def _available_models() -> list[dict[str, Any]]:
    req = urllib.request.Request(
        url=f"{settings.ollama_base_url}/api/tags",
        headers={"Content-Type": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=settings.ollama_timeout_seconds) as response:
            raw = response.read().decode("utf-8", errors="ignore")
    except urllib.error.URLError:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    models = data.get("models") or []
    return [model for model in models if isinstance(model, dict)]


def _first_available_model() -> str | None:
    models = _available_models()
    if not models:
        return None
    return str(models[0].get("name") or "") or None


def _fastest_available_model() -> str | None:
    models = _available_models()
    if not models:
        return None

    preferred_substrings = [
        "0.5b",
        "1b",
        "1.5b",
        "2b",
        "3b",
        "mini",
        "small",
    ]

    def sort_key(model: dict[str, Any]) -> tuple[int, int]:
        name = str(model.get("name") or "").lower()
        size = int(model.get("size") or 0)
        has_fast_hint = 0 if any(token in name for token in preferred_substrings) else 1
        return (has_fast_hint, size)

    fastest = sorted(models, key=sort_key)[0]
    return str(fastest.get("name") or "") or None


def _extract_json_block(text: str) -> dict[str, Any] | None:
    text = text.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return None

    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

    if isinstance(parsed, dict):
        return parsed
    return None


def _clamp_probability(value: Any) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, num))


def _extract_from_text(text: str, category_hint: str, model_used: str) -> LLMAssessment:
    clean = text.strip()
    risk_match = re.search(r"(?:p[_\s-]?risk|risk(?:\s+score)?|probability)\s*[:=]\s*([01](?:\.\d+)?)", clean, flags=re.IGNORECASE)
    if not risk_match:
        risk_match = re.search(r"\b([01](?:\.\d+)?)\b", clean)

    p_risk = _clamp_probability(risk_match.group(1)) if risk_match else 0.5

    category_match = re.search(r"category\s*[:=]\s*([a-zA-Z0-9 _-]{3,40})", clean, flags=re.IGNORECASE)
    if category_match:
        category = category_match.group(1).strip().lower().replace(" ", "-")
    else:
        category = (category_hint or "unknown").strip().lower() or "unknown"

    return LLMAssessment(
        p_risk=p_risk,
        category=category[:60],
        rationale=clean[:220],
        model_used=model_used,
    )


def assess_domain_with_ollama(domain: str, context: str = "", category_hint: str = "unknown") -> LLMAssessment:
    prompt = (
        "You are a strict child-safety risk scorer for DNS filtering. "
        "Your job is to evaluate domains and assign a risk score (p_risk) from 0.0 to 1.0 for child safety.\n\n"
        "SCORING RULES:\n"
        "- 0.95-1.0: Definitely harmful (porn, extreme violence, self-harm, hard drugs)\n"
        "- 0.80-0.94: Very likely harmful (gambling, dating, tobacco, alcohol sales, dark web)\n"
        "- 0.50-0.79: Potentially harmful (social media with adult content, forums with NSFW, piracy)\n"
        "- 0.20-0.49: Mildly concerning (general social media, gaming, mixed content)\n"
        "- 0.00-0.19: Safe (education, news, productivity, kids content)\n\n"
        "WHEN IN DOUBT, SCORE HIGHER. Children's safety is the priority.\n\n"
        "EXAMPLES:\n"
        '{"p_risk": 0.98, "category": "adult-content", "rationale": "Major pornography site, extremely unsafe for minors"}\n'
        '{"p_risk": 0.95, "category": "gambling", "rationale": "Online casino with real money betting"}\n'
        '{"p_risk": 0.85, "category": "dating", "rationale": "Adult dating platform not suitable for children"}\n'
        '{"p_risk": 0.60, "category": "social-media", "rationale": "Social platform with user-generated content, some NSFW"}\n'
        '{"p_risk": 0.15, "category": "education", "rationale": "Educational resource for students"}\n'
        '{"p_risk": 0.05, "category": "kids", "rationale": "Children\'s educational game site"}\n\n'
        "Return JSON only with keys: p_risk (float 0.0-1.0), category (short string), rationale (max 200 chars).\n\n"
        f"Domain to evaluate: {domain}\n"
        f"Category hint: {category_hint}\n"
    )
    if context:
        prompt += f"Internet context (may be partial):\n{context[:4000]}\n"

    model_name = settings.ollama_model or _fastest_available_model() or _first_available_model()
    if not model_name:
        raise RuntimeError("ollama_no_models_available")

    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": settings.ollama_temperature,
            "num_predict": settings.ollama_num_predict,
        },
        "format": "json",
    }

    req = urllib.request.Request(
        url=f"{settings.ollama_base_url}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=settings.ollama_timeout_seconds) as response:
            raw = response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            fallback = _fastest_available_model() or _first_available_model()
            if fallback and fallback != model_name:
                payload["model"] = fallback
                model_name = fallback
                retry_req = urllib.request.Request(
                    url=f"{settings.ollama_base_url}/api/generate",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(retry_req, timeout=settings.ollama_timeout_seconds) as response:
                        raw = response.read().decode("utf-8", errors="ignore")
                except urllib.error.URLError as retry_exc:
                    raise RuntimeError(f"ollama_unreachable: {retry_exc}") from retry_exc
            else:
                raise RuntimeError("ollama_model_not_found_and_no_fallback") from exc
        else:
            raise RuntimeError(f"ollama_http_error: {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"ollama_unreachable: {exc}") from exc

    # ── Parse Ollama response ──
    # Ollama returns: {"model":"...", "response":"<inner JSON string>", ...}
    # We need to extract the INNER response field, then parse that as JSON.
    response_json = None
    text_response = raw

    try:
        outer = json.loads(raw)
        inner_text = str(outer.get("response") or "")
        text_response = inner_text
        # The inner text should be JSON when format:"json" is used
        response_json = _extract_json_block(inner_text)
    except (json.JSONDecodeError, ValueError):
        # raw might be plain text or malformed
        response_json = _extract_json_block(raw)

    # Fallback: try parsing raw itself if inner parse failed
    if not response_json:
        response_json = _extract_json_block(raw)
        # If we got the outer envelope, check if it has p_risk directly
        if response_json and "p_risk" not in response_json:
            response_json = None

    if not response_json:
        return _extract_from_text(text_response, category_hint, model_name)

    return LLMAssessment(
        p_risk=_clamp_probability(response_json.get("p_risk")),
        category=str(response_json.get("category") or category_hint or "unknown")[:60],
        rationale=str(response_json.get("rationale") or "")[:220],
        model_used=model_name,
    )
