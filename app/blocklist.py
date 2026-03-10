from __future__ import annotations

"""
Multi-signal domain risk scorer.

Signal 1: Seed blocklist — curated list of known-harmful domains → instant p_risk=1.0
Signal 2: Keyword heuristics — pattern matching on domain name → instant p_risk 0.7-1.0
Signal 3: Ollama LLM — contextual analysis (handled in llm.py, called as fallback)
"""

import re

# ── Signal 1: Seed Blocklist ─────────────────────────────────

SEED_BLOCKLIST: dict[str, list[str]] = {
    "adult-content": [
        "pornhub.com", "xvideos.com", "xhamster.com", "xnxx.com", "redtube.com",
        "youporn.com", "tube8.com", "spankbang.com", "chaturbate.com", "bongacams.com",
        "stripchat.com", "cam4.com", "livejasmin.com", "brazzers.com", "bangbros.com",
        "realitykings.com", "naughtyamerica.com", "mofos.com", "onlyfans.com", "fansly.com",
        "manyvids.com", "clips4sale.com", "porntrex.com", "eporner.com", "hqporner.com",
        "youjizz.com", "tnaflix.com", "drtuber.com", "sexvid.xxx", "beeg.com",
        "porn.com", "sex.com", "fuq.com", "thumbzilla.com", "4tube.com",
        "sunporno.com", "txxx.com", "fapello.com", "rule34.xxx", "nhentai.net",
        "hentaihaven.xxx", "hanime.tv", "motherless.com", "xvideos2.com", "pornpics.com",
        "imagefap.com", "literotica.com", "redgifs.com", "erome.com", "ashemaletube.com",
        "javhd.com", "javmost.com", "hentai2read.com", "myreadingmanga.info",
        "playvids.com", "ixxx.com", "porndude.com", "nudevista.com", "pornmd.com",
        "tblop.com", "heavy-r.com", "efukt.com", "xhamsterlive.com", "camsoda.com",
        "myfreecams.com", "flirt4free.com", "imlive.com", "streamate.com",
        "pornhubpremium.com", "fakehub.com", "teamskeet.com", "blacked.com",
        "tushy.com", "vixen.com", "deeper.com", "bellesa.co",
    ],
    "gambling": [
        "bet365.com", "draftkings.com", "fanduel.com", "betway.com", "888casino.com",
        "pokerstars.com", "williamhill.com", "bovada.lv", "stake.com", "roobet.com",
        "rollbit.com", "betmgm.com", "caesars.com", "pointsbet.com", "unibet.com",
        "bwin.com", "ladbrokes.com", "paddypower.com", "betfair.com", "sportingbet.com",
        "1xbet.com", "22bet.com", "melbet.com", "parimatch.com", "mostbet.com",
        "betonline.ag", "mybookie.ag", "betrivers.com", "wynnbet.com", "twinspires.com",
        "virgin-bet.com", "partypoker.com", "888poker.com", "ggpoker.com",
        "casumo.com", "leovegas.com", "mrgreen.com", "rizk.com", "karamba.com",
        "betsson.com", "10bet.com", "sportsbet.com.au", "tab.com.au", "neds.com.au",
    ],
    "drugs-alcohol": [
        "leafly.com", "weedmaps.com", "erowid.org", "shroomery.org",
        "dutchie.com", "iheartjane.com", "grassdoor.com", "getnugg.com",
        "drizly.com", "minibar.com", "totalwine.com",
    ],
    "violence-gore": [
        "bestgore.fun", "theync.com", "documentingreality.com", "crazyshit.com",
        "liveleak.com", "goregrish.com", "kaotic.com", "seegore.com",
    ],
    "self-harm": [
        "lostallhope.com",
    ],
    "piracy": [
        "thepiratebay.org", "1337x.to", "rarbg.to", "yts.mx", "fitgirl-repacks.site",
        "nyaa.si", "rutracker.org", "torrentgalaxy.to", "limetorrents.info",
        "kickasstorrents.to", "torrentz2.eu", "magnetdl.com", "torlock.com",
        "zooqle.com", "seedpeer.me",
    ],
    "dating": [
        "tinder.com", "bumble.com", "grindr.com", "ashley-madison.com",
        "adultfriendfinder.com", "seeking.com", "sugardaddy.com", "feeld.co",
        "pureapp.com", "badoo.com", "okcupid.com", "match.com", "zoosk.com",
        "hinge.co", "plenty-of-fish.com", "pof.com", "tagged.com", "skout.com",
    ],
    "dark-web-proxy": [
        "tor2web.org", "onion.ws", "onion.pet", "onion.ly",
        "hide.me", "hidemyass.com",
    ],
    "weapons": [
        "gunbroker.com", "armslist.com", "budsgunshop.com", "cheaperthandirt.com",
        "palmettostatearmory.com", "midwayusa.com", "brownells.com",
    ],
}


def _build_lookup() -> dict[str, str]:
    """Build a flat domain → category lookup from the seed list."""
    lookup: dict[str, str] = {}
    for category, domains in SEED_BLOCKLIST.items():
        for domain in domains:
            lookup[domain.strip().lower()] = category
    return lookup


SEED_LOOKUP: dict[str, str] = _build_lookup()


def check_seed_blocklist(domain: str) -> tuple[bool, str]:
    """Check if a domain (or its parent) is in the seed blocklist."""
    domain = domain.strip().lower()

    if domain in SEED_LOOKUP:
        return True, SEED_LOOKUP[domain]

    if domain.startswith("www."):
        bare = domain[4:]
        if bare in SEED_LOOKUP:
            return True, SEED_LOOKUP[bare]

    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in SEED_LOOKUP:
            return True, SEED_LOOKUP[parent]

    return False, ""


# ── Signal 2: Keyword Heuristics ─────────────────────────────

# Keyword patterns with associated risk and category
_KEYWORD_RULES: list[tuple[str, float, str]] = [
    # Adult — very high confidence keywords
    (r"porn", 0.95, "adult-content"),
    (r"xxx", 0.95, "adult-content"),
    (r"xvideo", 0.90, "adult-content"),
    (r"xhamster", 0.95, "adult-content"),
    (r"hentai", 0.90, "adult-content"),
    (r"milf", 0.90, "adult-content"),
    (r"nsfw", 0.85, "adult-content"),
    (r"nude", 0.80, "adult-content"),
    (r"naked", 0.80, "adult-content"),
    (r"boob", 0.80, "adult-content"),
    (r"fetish", 0.85, "adult-content"),
    (r"escort", 0.85, "adult-content"),
    (r"camgirl", 0.90, "adult-content"),
    (r"livecam", 0.80, "adult-content"),
    (r"webcam.*adult", 0.85, "adult-content"),
    (r"onlyfan", 0.85, "adult-content"),
    (r"fap", 0.85, "adult-content"),
    (r"anal(?!ytic)", 0.75, "adult-content"),
    (r"sex(?!t|pert|ton)", 0.70, "adult-content"),
    (r"strip(?:club|per|teas)", 0.80, "adult-content"),
    (r"erotic", 0.80, "adult-content"),
    (r"stripper", 0.80, "adult-content"),
    (r"dildo", 0.85, "adult-content"),
    (r"orgasm", 0.85, "adult-content"),
    (r"blowjob", 0.95, "adult-content"),
    (r"cumshot", 0.95, "adult-content"),
    (r"hardcore", 0.70, "adult-content"),

    # Gambling
    (r"casino", 0.85, "gambling"),
    (r"poker(?!mon)", 0.80, "gambling"),
    (r"betting", 0.80, "gambling"),
    (r"gambl", 0.85, "gambling"),
    (r"slots(?!car)", 0.80, "gambling"),
    (r"sportsbet", 0.85, "gambling"),
    (r"bet(?:365|way|fair|mgm|rivers|online)", 0.90, "gambling"),
    (r"blackjack", 0.80, "gambling"),
    (r"roulette", 0.80, "gambling"),
    (r"jackpot", 0.75, "gambling"),
    (r"odds(?:shark|checker)", 0.70, "gambling"),

    # Drugs
    (r"weed(?!s\.)", 0.70, "drugs-alcohol"),
    (r"marijuana", 0.70, "drugs-alcohol"),
    (r"cannabis", 0.65, "drugs-alcohol"),
    (r"dispensary", 0.65, "drugs-alcohol"),
    (r"shroom", 0.70, "drugs-alcohol"),
    (r"cocaine", 0.85, "drugs-alcohol"),
    (r"heroin", 0.85, "drugs-alcohol"),
    (r"mdma", 0.85, "drugs-alcohol"),
    (r"darknet.*market", 0.90, "drugs-alcohol"),

    # Violence
    (r"gore\b", 0.85, "violence-gore"),
    (r"bestgore", 0.95, "violence-gore"),
    (r"death.*video", 0.80, "violence-gore"),
    (r"murder.*video", 0.80, "violence-gore"),
    (r"execution.*video", 0.85, "violence-gore"),
    (r"cartel.*video", 0.80, "violence-gore"),

    # Piracy
    (r"torrent(?!ial)", 0.65, "piracy"),
    (r"pirate.*bay", 0.90, "piracy"),
    (r"crack(?:ed)?(?:app|soft|game)", 0.80, "piracy"),
    (r"warez", 0.80, "piracy"),
    (r"keygen", 0.75, "piracy"),

    # Dating
    (r"hookup", 0.75, "dating"),
    (r"sugar.*daddy", 0.80, "dating"),
    (r"sugar.*mama", 0.80, "dating"),
    (r"adult.*dating", 0.85, "dating"),
    (r"booty.*call", 0.80, "dating"),

    # Weapons
    (r"buy.*gun", 0.75, "weapons"),
    (r"gun.*shop", 0.70, "weapons"),
    (r"ammo.*store", 0.70, "weapons"),
    (r"firearm.*sale", 0.70, "weapons"),

    # Extremism / hate
    (r"jihadist", 0.90, "extremism"),
    (r"isis(?:media|news|official)", 0.95, "extremism"),
    (r"white.*supremac", 0.90, "extremism"),
    (r"neo.*nazi", 0.90, "extremism"),

    # Self-harm
    (r"suicide.*method", 0.95, "self-harm"),
    (r"how.*to.*kill.*myself", 0.95, "self-harm"),
    (r"selfharm(?:tip|guide|method)", 0.90, "self-harm"),
    (r"pro\s*ana\b", 0.85, "self-harm"),
    (r"thinspiration", 0.80, "self-harm"),

    # Crypto scams / dark market
    (r"darkmarket", 0.90, "dark-web-proxy"),
    (r"darkweb", 0.85, "dark-web-proxy"),
    (r"silk\s?road", 0.90, "dark-web-proxy"),
    (r"onion.*market", 0.90, "dark-web-proxy"),
    (r"drug.*market", 0.85, "drugs-alcohol"),
    (r"buy.*cocaine", 0.95, "drugs-alcohol"),
    (r"buy.*heroin", 0.95, "drugs-alcohol"),
    (r"buy.*meth", 0.95, "drugs-alcohol"),
    (r"buy.*weed.*online", 0.80, "drugs-alcohol"),

    # Trading / financial exploitation
    (r"forex.*scam", 0.80, "scam"),
    (r"crypto.*doubl", 0.85, "scam"),
    (r"ponzi", 0.80, "scam"),

    # Phishing / suspicious patterns
    (r"secure.*login.*bank", 0.70, "phishing"),
    (r"verify.*account.*now", 0.65, "phishing"),
    (r"paypa[l1].*login", 0.85, "phishing"),
    (r"amazo[n0].*signin", 0.80, "phishing"),
]

# Risky TLDs that boost risk slightly
_RISKY_TLDS = {
    ".xxx", ".adult", ".sex", ".porn", ".cam", ".sexy", ".dating",
    ".bet", ".casino", ".poker", ".gambling",
}


def score_domain_keywords(domain: str) -> tuple[float, str]:
    """Score a domain based on keyword patterns in the domain name.

    Returns (risk_score, category). risk_score=0.0 means no keyword match.
    """
    domain_lower = domain.strip().lower()
    # Strip scheme if present (use proper prefix removal, not lstrip which strips characters)
    full_domain = domain_lower
    if full_domain.startswith("https://"):
        full_domain = full_domain[8:]
    elif full_domain.startswith("http://"):
        full_domain = full_domain[7:]
    # Also strip trailing path
    full_domain = full_domain.split("/")[0]
    # Also match against just the name part (before last TLD)
    name_part = full_domain.rsplit(".", 1)[0] if "." in full_domain else full_domain

    best_risk = 0.0
    best_category = ""

    for pattern, risk, category in _KEYWORD_RULES:
        # Check both name part and full domain for broader coverage
        if re.search(pattern, name_part, re.IGNORECASE) or re.search(pattern, full_domain, re.IGNORECASE):
            if risk > best_risk:
                best_risk = risk
                best_category = category

    # Risky TLD bonus — these TLDs strongly indicate adult/gambling content
    for tld in _RISKY_TLDS:
        if full_domain.endswith(tld):
            best_risk = max(best_risk, 0.80)
            if not best_category:
                best_category = "adult-content"
            break

    # Suspicious hyphen-heavy or number-padding domains (phishing pattern)
    # e.g., paypal-secure-login.com, amazon-account-verify.net
    hyphen_count = name_part.count("-")
    if hyphen_count >= 3 and best_risk < 0.50:
        best_risk = max(best_risk, 0.45)
        if not best_category:
            best_category = "suspicious"

    return best_risk, best_category


def assess_domain_multi_signal(domain: str) -> tuple[float, str, str]:
    """Run all local signals on a domain.

    Returns (risk_score, category, source) where source is one of:
    'seed_blocklist', 'keyword_heuristic', or 'none' (needs LLM).
    """
    # Signal 1: Seed blocklist
    is_blocked, seed_cat = check_seed_blocklist(domain)
    if is_blocked:
        return 1.0, seed_cat, "seed_blocklist"

    # Signal 2: Keyword heuristics
    kw_risk, kw_cat = score_domain_keywords(domain)
    if kw_risk >= 0.60:
        return kw_risk, kw_cat, "keyword_heuristic"

    return 0.0, "", "none"
