"""
ai_analyzer.py
--------------
What this is: the "contextual reasoning" layer of CyberShield AI. The
brief asks for "AI analysis" on top of the rule-based engine. Because
this build has a strict zero-third-party-dependency rule (no SDKs, and
we're not standing up an external network call to a paid model), this
module simulates that reasoning step deterministically: it looks at
WHICH indicators fired together and synthesizes a natural-language
read of the situation, the same way a human analyst would talk through
"why this looks like X".

Why it's built this way (and not skipped): the hackathon brief is
explicit that the whole system must NOT depend blindly on an LLM, and
must keep working if "AI" is unavailable. This module IS that fallback
— always on, always available, and 100% consistent with the transparent
scoring in threat_detector.py (it never invents a verdict the score
doesn't support).

If you later get explicit confirmation that calling a real external LLM
API is allowed, this is the one file you would change — everything else
(analyzer.py, url_analyzer.py, threat_detector.py) stays untouched,
because they don't know or care where the "AI note" comes from.

No external packages — pure Python standard library.
"""

# Short, natural-language "reads" keyed by which indicator combos are present.
# Order matters: the first matching rule below is used, so put the most
# specific / severe combinations first.
_CONTEXT_RULES = [
    (
        {"credential_request", "impersonation", "urgency"},
        "This message combines urgency, impersonation of a trusted "
        "organization, and a request for private credentials — a classic "
        "phishing pattern designed to make you act before you think.",
    ),
    (
        {"financial_request", "urgency"},
        "The message pressures you to act quickly while also asking for "
        "money or payment details, which is a common structure in "
        "financial scams.",
    ),
    (
        {"unrealistic_reward"},
        "The message promises a prize or reward that is unlikely to be "
        "genuine — legitimate organizations rarely notify winners this way.",
    ),
    (
        {"credential_request"},
        "The message asks you to verify or re-enter sensitive credentials, "
        "which legitimate services rarely request through a message or link.",
    ),
    (
        {"impersonation"},
        "The message presents itself as coming from a bank, company, or "
        "government body, but this cannot be verified from the message text "
        "alone.",
    ),
    (
        {"urgency", "threat_language"},
        "The message uses pressure and alarming language to provoke a fast, "
        "less careful reaction — a common social-engineering tactic.",
    ),
]

_URL_CONTEXT_RULES = [
    (
        {"ip_address_host"},
        "The link points to a raw numeric address instead of a named "
        "domain, which is unusual for legitimate websites and often used "
        "to obscure the real destination.",
    ),
    (
        {"at_symbol"},
        "The link contains an '@' symbol, a known technique for making a "
        "link appear to go to one destination while actually pointing "
        "elsewhere.",
    ),
    (
        {"suspicious_keywords", "not_https"},
        "The link uses account/login-related wording without a secure "
        "connection, a combination often seen in credential-harvesting "
        "pages.",
    ),
    (
        {"suspicious_tld"},
        "The link uses a domain ending that is inexpensive and frequently "
        "abused for short-lived scam or phishing sites.",
    ),
]


def _pick_context_note(fired_keys: set, rules: list) -> str:
    for required_keys, note in rules:
        if required_keys.issubset(fired_keys):
            return note
    return None


def generate_ai_note(message_indicators: dict = None, url_indicators: dict = None) -> dict:
    """
    Produce a short contextual note synthesizing the detected indicators,
    the way a human analyst would explain "why" in one or two sentences.

    This never runs alone — it only comments on indicators already found
    by the rule-based engine, so it can't introduce a false signal.

    Returns:
        {
            "available": True,   # always True; this layer has no external
                                  # dependency, so it never "goes down"
            "note": str or None,
        }
    """
    message_indicators = message_indicators or {}
    url_indicators = url_indicators or {}

    fired_message_keys = {k for k, v in message_indicators.items() if v}
    fired_url_keys = {k for k, v in url_indicators.items() if v}

    note = _pick_context_note(fired_message_keys, _CONTEXT_RULES)
    if note is None:
        note = _pick_context_note(fired_url_keys, _URL_CONTEXT_RULES)

    if note is None:
        if fired_message_keys or fired_url_keys:
            note = (
                "Some individual characteristics were detected, but no "
                "strong combined pattern of a known scam type was found. "
                "Stay cautious and verify through an official channel if "
                "anything feels off."
            )
        else:
            note = (
                "No known manipulation patterns or structural red flags "
                "were detected. This does not guarantee the content is "
                "safe — always stay alert to context CyberShield AI cannot "
                "see."
            )

    return {"available": True, "note": note}