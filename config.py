"""
config.py
---------
What this is: a single place that holds every "rule" CyberShield AI uses
to judge a message or URL — keyword lists, how much each suspicious sign
is worth, and where the LOW/MEDIUM/HIGH/CRITICAL cutoffs are.

Why it exists: judges (and you, at 2am) should be able to open ONE file
and see exactly why the system flags what it flags. Nothing here is a
"black box" — every number is a deliberate weight you can explain.

No external packages are used anywhere in this project — only Python's
standard library. This file itself has zero imports beyond that.
"""

# ---------------------------------------------------------------------------
# RISK LEVEL THRESHOLDS
# ---------------------------------------------------------------------------
# A risk score is always 0-100. These ranges turn that number into a label
# a normal person understands at a glance.
RISK_THRESHOLDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
]

# Colors used consistently across the web UI for each risk level.
RISK_COLORS = {
    "CRITICAL": "#ff3b5c",
    "HIGH": "#ff8a3d",
    "MEDIUM": "#ffd23f",
    "LOW": "#2de6a6",
}

# ---------------------------------------------------------------------------
# MESSAGE ANALYSIS — INDICATOR KEYWORD GROUPS
# ---------------------------------------------------------------------------
# Each group is a real-world manipulation tactic. If any phrase in a group
# is found in the user's message (case-insensitive), that group "fires"
# and contributes its weight (below) to the total score once — we don't
# stack the same tactic twice just because it used two phrases.

URGENCY_PHRASES = [
    "act now", "immediately", "urgent", "right away", "as soon as possible",
    "will be blocked", "will be suspended", "will be closed", "expires today",
    "expires in", "last chance", "final notice", "24 hours", "within 24",
    "before it's too late", "time-sensitive", "respond now",
]

THREAT_LANGUAGE = [
    "account will be blocked", "account will be suspended",
    "legal action", "you will be fined", "you will be charged",
    "arrest", "penalty", "your account has been compromised",
    "unauthorized access detected", "suspicious activity detected",
]

CREDENTIAL_REQUEST = [
    "verify your account", "confirm your password", "enter your password",
    "update your password", "confirm your identity", "verify your identity",
    "login to verify", "provide your otp", "share your otp", "enter your pin",
    "confirm your card number", "verify your card", "ssn", "social security",
    "aadhaar", "verify your details",
]

FINANCIAL_REQUEST = [
    "send money", "wire transfer", "gift card", "bank details",
    "account number", "processing fee", "pay a fee", "claim your refund",
    "transfer fee", "unlock your funds", "pay now to release",
    "small fee to claim", "advance fee",
]

IMPERSONATION_PHRASES = [
    "this is your bank", "official notice from", "on behalf of",
    "government notice", "irs", "tax refund", "customs department",
    "delivery failed", "your package", "courier service", "amazon support",
    "microsoft support", "apple support", "tech support team",
]

UNREALISTIC_REWARD = [
    "you have won", "you've won", "claim your prize", "lottery",
    "congratulations you", "free gift", "selected as a winner",
    "cash prize", "reward waiting",
]

SUSPICIOUS_INSTRUCTIONS = [
    "click this link", "click here", "clicking this link", "clicking here",
    "download the attachment", "open the attached file", "do not tell anyone",
    "keep this confidential", "forward this to", "share this with",
    "install this app",
]

# Weight = how many points this tactic contributes if detected at least once.
# These are additive and capped at 100 in threat_detector.py.
INDICATOR_WEIGHTS = {
    "urgency": 15,
    "threat_language": 15,
    "credential_request": 25,
    "financial_request": 20,
    "impersonation": 15,
    "unrealistic_reward": 15,
    "suspicious_instructions": 10,
    "suspicious_url_in_message": 15,
}

INDICATOR_GROUPS = {
    "urgency": URGENCY_PHRASES,
    "threat_language": THREAT_LANGUAGE,
    "credential_request": CREDENTIAL_REQUEST,
    "financial_request": FINANCIAL_REQUEST,
    "impersonation": IMPERSONATION_PHRASES,
    "unrealistic_reward": UNREALISTIC_REWARD,
    "suspicious_instructions": SUSPICIOUS_INSTRUCTIONS,
}

# Human-readable labels for each indicator, used in the results screen.
INDICATOR_LABELS = {
    "urgency": "Creates artificial urgency or time pressure",
    "threat_language": "Uses threatening or alarming language",
    "credential_request": "Requests passwords, PINs, or identity verification",
    "financial_request": "Requests money, gift cards, or bank details",
    "impersonation": "Impersonates a bank, company, or official body",
    "unrealistic_reward": "Promises an unrealistic prize or reward",
    "suspicious_instructions": "Pushes you toward a link, download, or secrecy",
    "suspicious_url_in_message": "Contains a suspicious link",
}

# ---------------------------------------------------------------------------
# URL ANALYSIS
# ---------------------------------------------------------------------------
URL_SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "bank", "webscr", "invoice", "billing", "suspended",
    "unlock", "recovery", "support", "wallet",
]

# Weight = points if this URL characteristic is present.
URL_INDICATOR_WEIGHTS = {
    "not_https": 15,
    "ip_address_host": 30,
    "excessive_subdomains": 15,
    "long_url": 10,
    "suspicious_keywords": 15,
    "suspicious_chars": 15,
    "at_symbol": 20,
    "encoded_chars": 10,
    "many_hyphens": 10,
    "suspicious_tld": 10,
}

URL_INDICATOR_LABELS = {
    "not_https": "Does not use a secure HTTPS connection",
    "ip_address_host": "Uses a raw IP address instead of a domain name",
    "excessive_subdomains": "Has an unusually high number of subdomains",
    "long_url": "Unusually long URL, often used to hide the real destination",
    "suspicious_keywords": "Contains keywords commonly used in phishing URLs",
    "suspicious_chars": "Contains unusual or suspicious characters",
    "at_symbol": "Contains an '@' symbol, which can hide the real destination",
    "encoded_chars": "Contains encoded characters that may hide the real URL",
    "many_hyphens": "Contains an unusually high number of hyphens",
    "suspicious_tld": "Uses a domain ending commonly abused for scams",
}

SUSPICIOUS_TLDS = [".zip", ".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"]

# Length above which a URL is considered "long" for phishing-obfuscation purposes.
URL_LONG_THRESHOLD = 75
URL_MAX_SUBDOMAINS = 3
URL_MAX_HYPHENS = 4

# ---------------------------------------------------------------------------
# INPUT SAFETY LIMITS
# ---------------------------------------------------------------------------
MAX_MESSAGE_LENGTH = 5000
MAX_URL_LENGTH = 2048