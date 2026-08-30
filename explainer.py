"""
explainer.py
------------
What this is: turns the risk score + indicators into two explanations —
one in plain, everyday language ("Simple Explanation") and one using
correct security terminology ("Technical Analysis") — plus a short list
of recommended actions.

Why it exists: the brief calls this out as a standout feature. A risk
score alone ("73/100") doesn't help someone who isn't a security expert
decide what to do. This module is the translation layer between the
numbers and a normal person's next move.

No external packages — pure Python standard library.
"""

RECOMMENDED_ACTIONS = {
    "CRITICAL": {
        "avoid": [
            "Don't click any links in this message",
            "Don't enter your password, PIN, or OTP anywhere it leads",
            "Don't send money or gift cards",
        ],
        "do": [
            "Verify by contacting the organization directly using a number "
            "or website you already trust (not one from this message)",
            "Report and delete the message",
        ],
    },
    "HIGH": {
        "avoid": [
            "Don't click any links in this message",
            "Don't share personal or financial information",
        ],
        "do": [
            "Verify through the organization's official app or website",
            "When in doubt, don't respond",
        ],
    },
    "MEDIUM": {
        "avoid": [
            "Be cautious with any links or requests in this message",
        ],
        "do": [
            "Double-check the sender's identity before responding",
            "Look up the organization independently if it claims urgency",
        ],
    },
    "LOW": {
        "avoid": [],
        "do": [
            "No strong red flags found, but always stay alert to context "
            "CyberShield AI can't see (like whether you were expecting "
            "this message)",
        ],
    },
}


def _simple_explanation(level: str, category: str, contributing: list) -> str:
    if not contributing:
        return (
            "This doesn't show the common warning signs CyberShield AI "
            "looks for. It's probably fine, but if something about it "
            "still feels off, trust that instinct."
        )

    top_reasons = [item["label"].lower() for item in contributing[:3]]
    reasons_text = "; ".join(top_reasons)

    if level in ("CRITICAL", "HIGH"):
        return (
            f"\u26a0\ufe0f This looks risky. It {reasons_text}. "
            "Don't click any links, don't share your password or bank "
            "details, and don't send money."
        )
    if level == "MEDIUM":
        return (
            f"This message has some warning signs — it {reasons_text}. "
            "It might be genuine, but treat it carefully and verify "
            "before acting on it."
        )
    return (
        f"This shows a minor warning sign — it {reasons_text}. "
        "It's likely low-risk, but stay alert."
    )


def _technical_explanation(category: str, contributing: list) -> str:
    if not contributing:
        return (
            "No indicators from the current rule set were matched. "
            "Absence of detected indicators is not proof of legitimacy — "
            "it reflects the limits of pattern-based detection."
        )

    indicator_list = ", ".join(item["label"] for item in contributing)
    return (
        f"Classification: {category}. Detected indicators: {indicator_list}. "
        f"Score is the additive sum of weighted indicators (see breakdown), "
        f"capped at 100, and is deterministic given the same input."
    )


def build_explanation(verdict: dict, ai_note: dict) -> dict:
    """
    Build the full explanation payload for the results screen.

    verdict: the dict returned by threat_detector.evaluate()
    ai_note: the dict returned by ai_analyzer.generate_ai_note()

    Returns:
        {
            "simple": str,
            "technical": str,
            "ai_context": str,
            "recommended_actions": {"avoid": [...], "do": [...]},
        }
    """
    level = verdict["level"]
    category = verdict["category"]
    contributing = verdict["contributing_indicators"]

    return {
        "simple": _simple_explanation(level, category, contributing),
        "technical": _technical_explanation(category, contributing),
        "ai_context": ai_note.get("note", ""),
        "recommended_actions": RECOMMENDED_ACTIONS.get(level, RECOMMENDED_ACTIONS["LOW"]),
    }