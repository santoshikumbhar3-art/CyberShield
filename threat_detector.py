"""
threat_detector.py
-------------------
What this is: the "risk engine" of CyberShield AI. It takes the raw
indicators found by analyzer.py and/or url_analyzer.py and turns them
into ONE clear number (0-100), a risk level, and a threat category.

Why it exists: judges and users need one bottom-line answer, but that
answer must be traceable. This module never uses randomness — the score
is always: sum of weights for every indicator that fired, capped at 100.
That means anyone can look at the result and see exactly why the score
is what it is (see the "contributing_indicators" list in the output).

No external packages — pure Python standard library, no imports needed
beyond config.
"""

from config import (
    RISK_THRESHOLDS,
    INDICATOR_WEIGHTS,
    INDICATOR_LABELS,
    URL_INDICATOR_WEIGHTS,
    URL_INDICATOR_LABELS,
)


def _score_to_level(score: int) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def _classify_threat(message_indicators: dict, url_indicators: dict) -> str:
    """
    Pick a human-readable threat category based on which indicators fired.
    This is a simple priority order: the most specific / severe category
    that matches wins, so the label given is the most useful one.
    """
    if message_indicators.get("credential_request") and message_indicators.get("impersonation"):
        return "PHISHING DETECTED"
    if message_indicators.get("financial_request") and message_indicators.get("urgency"):
        return "FINANCIAL SCAM"
    if message_indicators.get("unrealistic_reward"):
        return "PRIZE / LOTTERY SCAM"
    if message_indicators.get("credential_request"):
        return "CREDENTIAL THEFT ATTEMPT"
    if message_indicators.get("impersonation"):
        return "IMPERSONATION ATTEMPT"
    if url_indicators.get("ip_address_host") or url_indicators.get("at_symbol"):
        return "SUSPICIOUS LINK STRUCTURE"
    if message_indicators.get("urgency") or message_indicators.get("threat_language"):
        return "SOCIAL ENGINEERING ATTEMPT"
    if any(url_indicators.values()):
        return "SUSPICIOUS URL"
    return "NO CLEAR THREAT DETECTED"


def evaluate(message_result: dict = None, url_result: dict = None) -> dict:
    """
    Combine message and/or URL analysis results into a final verdict.

    Either message_result or url_result (or both) can be provided — pass
    None for whichever type wasn't analyzed. Each should be the dict
    returned by analyzer.analyze_message() or url_analyzer.analyze_url().

    Returns a dict:
        {
            "score": int (0-100),
            "level": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
            "category": str,
            "confidence": "LOW"|"MEDIUM"|"HIGH",
            "contributing_indicators": [
                {"key":..., "label":..., "points":...}, ...
            ],
        }
    """
    message_indicators = (message_result or {}).get("indicators", {})
    url_indicators = (url_result or {}).get("indicators", {})

    total_score = 0
    contributing = []

    for key, fired in message_indicators.items():
        if fired and key in INDICATOR_WEIGHTS:
            points = INDICATOR_WEIGHTS[key]
            total_score += points
            contributing.append({
                "key": key,
                "label": INDICATOR_LABELS.get(key, key),
                "points": points,
            })

    # If the message contained a URL and that URL itself has red flags,
    # add the dedicated "suspicious_url_in_message" weight once.
    if message_result and message_result.get("urls_found") and url_result and url_result.get("valid"):
        if any(url_result["indicators"].values()):
            points = INDICATOR_WEIGHTS.get("suspicious_url_in_message", 0)
            total_score += points
            contributing.append({
                "key": "suspicious_url_in_message",
                "label": INDICATOR_LABELS.get("suspicious_url_in_message"),
                "points": points,
            })

    for key, fired in url_indicators.items():
        if fired and key in URL_INDICATOR_WEIGHTS:
            points = URL_INDICATOR_WEIGHTS[key]
            total_score += points
            contributing.append({
                "key": key,
                "label": URL_INDICATOR_LABELS.get(key, key),
                "points": points,
            })

    total_score = min(total_score, 100)
    level = _score_to_level(total_score)
    category = _classify_threat(message_indicators, url_indicators)

    # Confidence reflects how much evidence we found, not how "sure" we
    # are the content is malicious — we never claim certainty about intent.
    num_signals = len(contributing)
    if num_signals >= 4:
        confidence = "HIGH"
    elif num_signals >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "score": total_score,
        "level": level,
        "category": category,
        "confidence": confidence,
        "contributing_indicators": contributing,
    }