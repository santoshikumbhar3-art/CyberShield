"""
url_analyzer.py
----------------
What this is: the part of CyberShield AI that looks at a URL's
*structure* (not its content, since we can't safely visit suspicious
links) and flags characteristics that are common in phishing links.

Why it exists: phishing links often have telltale structural signs —
no HTTPS, a raw IP address instead of a real domain, way too many
subdomains, sneaky "@" tricks, etc. None of these alone PROVE a link is
malicious, so this module is careful to say "suspicious" rather than
"malicious" or "safe" — CyberShield AI never claims false certainty.

How it works (plain language): we break the URL into pieces (scheme,
domain, path) using Python's built-in urllib.parse, then run a checklist
against each piece.

No external packages — only Python's standard library
(urllib.parse, re).
"""

import re
from urllib.parse import urlparse

from config import (
    URL_SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_LONG_THRESHOLD,
    URL_MAX_SUBDOMAINS,
    URL_MAX_HYPHENS,
    MAX_URL_LENGTH,
)

IP_ADDRESS_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

SUSPICIOUS_CHAR_PATTERN = re.compile(r"[^\w\-./:%?=&#@]")


def _normalize(url: str) -> str:
    """Add a scheme if the user pasted a bare domain like 'example.com'."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return url


def analyze_url(raw_url: str) -> dict:
    """
    Inspect a URL's structure for common phishing red flags.

    Returns a dict:
        {
            "valid": bool,
            "error": str or None,
            "indicators": {characteristic_name: True/False, ...},
            "details": {characteristic_name: "explanation string", ...},
            "parsed": {"scheme":..., "host":..., "path":...},
        }
    """
    if raw_url is None or not raw_url.strip():
        return {
            "valid": False,
            "error": "Please enter a URL to analyze.",
            "indicators": {},
            "details": {},
            "parsed": {},
        }

    if len(raw_url) > MAX_URL_LENGTH:
        return {
            "valid": False,
            "error": f"URL is too long (max {MAX_URL_LENGTH} characters).",
            "indicators": {},
            "details": {},
            "parsed": {},
        }

    normalized = _normalize(raw_url)

    try:
        parsed = urlparse(normalized)
    except ValueError:
        return {
            "valid": False,
            "error": "This does not look like a valid URL.",
            "indicators": {},
            "details": {},
            "parsed": {},
        }

    host = parsed.hostname or ""
    if not host:
        return {
            "valid": False,
            "error": "This does not look like a valid URL.",
            "indicators": {},
            "details": {},
            "parsed": {},
        }

    full_url_lower = normalized.lower()
    indicators = {}
    details = {}

    # HTTPS check
    indicators["not_https"] = parsed.scheme != "https"

    # Raw IP address as host
    indicators["ip_address_host"] = bool(IP_ADDRESS_PATTERN.match(host))

    # "@" symbol trick: everything before "@" is ignored by browsers,
    # so "real-bank.com@evil.com" actually goes to evil.com.
    indicators["at_symbol"] = "@" in normalized

    # Subdomain count, e.g. "login.secure.mybank.evil.com" -> many parts
    host_parts = host.split(".")
    subdomain_count = max(0, len(host_parts) - 2)
    indicators["excessive_subdomains"] = subdomain_count > URL_MAX_SUBDOMAINS

    # Overall length
    indicators["long_url"] = len(normalized) > URL_LONG_THRESHOLD

    # Suspicious keywords anywhere in the URL
    matched_keywords = [kw for kw in URL_SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    indicators["suspicious_keywords"] = len(matched_keywords) > 0
    if matched_keywords:
        details["suspicious_keywords"] = ", ".join(sorted(set(matched_keywords)))

    # Unusual characters (outside a normal safe set for URLs)
    indicators["suspicious_chars"] = bool(SUSPICIOUS_CHAR_PATTERN.search(normalized))

    # Percent-encoded characters can hide the real destination or characters
    indicators["encoded_chars"] = "%" in normalized

    # Excessive hyphens, e.g. "paypal-secure-login-verify.com"
    indicators["many_hyphens"] = host.count("-") > URL_MAX_HYPHENS

    # Suspicious top-level domains often abused for cheap throwaway scam sites
    indicators["suspicious_tld"] = any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)

    return {
        "valid": True,
        "error": None,
        "indicators": indicators,
        "details": details,
        "parsed": {
            "scheme": parsed.scheme,
            "host": host,
            "path": parsed.path or "/",
        },
    }