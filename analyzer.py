"""
analyzer.py
-----------
What this is: the part of CyberShield AI that reads a suspicious message
(SMS, WhatsApp, email, etc.) and figures out WHICH manipulation tactics
it uses — urgency, fake threats, requests for your password, and so on.

Why it exists: scammers reuse the same psychological tricks over and
over. This module recognizes those tricks by matching known phrases,
so the risk score later on is based on real evidence, not guesswork.

How it works (plain language): we keep lists of common scam phrases,
grouped by "tactic" (see config.py). We check the message against every
group. If any phrase from a group appears, that tactic is marked as
"detected" for this message. We also pull out any URLs found inside the
message and hand them to url_analyzer.py, since a suspicious link inside
a message is itself a strong signal.

No external packages — only Python's standard library (re).
"""

import re

from config import (
    INDICATOR_GROUPS,
    MAX_MESSAGE_LENGTH,
)

# A simple, permissive URL-matching pattern good enough to spot links
# embedded in free-form text. It does not need to be a perfect URL
# validator — url_analyzer.py does the deep inspection separately.
URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+", re.IGNORECASE)


def extract_urls(message: str):
    """Find every URL-looking substring inside a message."""
    return URL_PATTERN.findall(message)


def analyze_message(message: str) -> dict:
    """
    Analyze a suspicious message and return which manipulation tactics
    were detected, plus any embedded URLs.

    Returns a dict:
        {
            "valid": bool,
            "error": str or None,
            "indicators": {tactic_name: True/False, ...},
            "matched_phrases": {tactic_name: [phrase, ...], ...},
            "urls_found": [url, ...],
        }
    """
    if message is None or not message.strip():
        return {
            "valid": False,
            "error": "Please enter a message to analyze.",
            "indicators": {},
            "matched_phrases": {},
            "urls_found": [],
        }

    if len(message) > MAX_MESSAGE_LENGTH:
        return {
            "valid": False,
            "error": (
                f"Message is too long (max {MAX_MESSAGE_LENGTH} characters). "
                "Please paste a shorter excerpt of the suspicious content."
            ),
            "indicators": {},
            "matched_phrases": {},
            "urls_found": [],
        }

    lowered = message.lower()

    indicators = {}
    matched_phrases = {}

    for tactic_name, phrase_list in INDICATOR_GROUPS.items():
        found = [phrase for phrase in phrase_list if phrase in lowered]
        indicators[tactic_name] = len(found) > 0
        if found:
            matched_phrases[tactic_name] = found

    urls_found = extract_urls(message)

    return {
        "valid": True,
        "error": None,
        "indicators": indicators,
        "matched_phrases": matched_phrases,
        "urls_found": urls_found,
    }