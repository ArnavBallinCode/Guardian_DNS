from __future__ import annotations
import re
import urllib.error
import urllib.parse
import urllib.request

from app.settings import settings


def _strip_html(raw: str) -> str:
    text = re.sub(r"<script[\s\S]*?</script>", " ", raw, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def fetch_url_text(url: str, max_chars: int) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return ""

    req = urllib.request.Request(
        url=url,
        headers={
            "User-Agent": "guardian-dns-mvp/0.1",
            "Accept": "text/html, text/plain;q=0.9",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=settings.fetch_timeout_seconds) as resp:
            content_type = (resp.headers.get("Content-Type") or "").lower()
            body = resp.read(settings.max_fetch_bytes).decode("utf-8", errors="ignore")
    except urllib.error.URLError:
        return ""

    if "html" in content_type:
        text = _strip_html(body)
    else:
        text = body

    return text[:max_chars]


def build_domain_context(domain: str, evidence_urls: list[str]) -> str:
    urls: list[str] = []

    if evidence_urls:
        urls.extend(evidence_urls[: settings.max_evidence_urls])

    if not urls:
        urls.append(f"https://{domain}")

    snippets: list[str] = []
    for url in urls:
        snippet = fetch_url_text(url, settings.max_context_chars_per_url)
        if snippet:
            snippets.append(f"URL: {url}\n{snippet}")

    return "\n\n".join(snippets)[: settings.max_total_context_chars]
