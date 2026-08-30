"""
test_threat_detector.py
------------------------
Tests for threat_detector.py — confirms the risk score is deterministic
(same input always gives the same output) and correctly derived from
detected indicators, per config.py weights.

Run with:
    python -m unittest tests.test_threat_detector -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import analyze_message
from url_analyzer import analyze_url
from threat_detector import evaluate


class TestThreatDetector(unittest.TestCase):

    def test_risk_score_is_deterministic(self):
        message = "Your bank account will be blocked today. Verify your account immediately."
        result1 = analyze_message(message)
        result2 = analyze_message(message)
        verdict1 = evaluate(message_result=result1)
        verdict2 = evaluate(message_result=result2)
        self.assertEqual(verdict1["score"], verdict2["score"])

    def test_no_indicators_gives_low_score(self):
        result = analyze_message("Hey, are we still on for lunch tomorrow?")
        verdict = evaluate(message_result=result)
        self.assertEqual(verdict["score"], 0)
        self.assertEqual(verdict["level"], "LOW")

    def test_phishing_message_scores_high_or_critical(self):
        message = (
            "URGENT: Your bank account will be blocked today. Verify your "
            "account immediately by clicking this link and confirm your password."
        )
        result = analyze_message(message)
        verdict = evaluate(message_result=result)
        self.assertGreaterEqual(verdict["score"], 60)
        self.assertIn(verdict["level"], ("HIGH", "CRITICAL"))

    def test_score_never_exceeds_100(self):
        message = (
            "URGENT act now! Your account will be blocked, legal action, "
            "verify your account, confirm your password, enter your pin, "
            "send money, wire transfer, gift card, on behalf of the irs, "
            "you have won a cash prize, click this link, do not tell anyone"
        )
        result = analyze_message(message)
        verdict = evaluate(message_result=result)
        self.assertLessEqual(verdict["score"], 100)

    def test_url_only_evaluation(self):
        url_result = analyze_url("http://192.168.1.1/verify-account@evil.com")
        verdict = evaluate(url_result=url_result)
        self.assertGreater(verdict["score"], 0)

    def test_confidence_scales_with_signal_count(self):
        low_signal = analyze_message("Please verify your account soon.")
        verdict_low = evaluate(message_result=low_signal)

        high_signal = analyze_message(
            "URGENT act now! Verify your account, confirm your password, "
            "send money, this is your bank, you have won a prize, click this link."
        )
        verdict_high = evaluate(message_result=high_signal)

        self.assertNotEqual(verdict_low["confidence"], verdict_high["confidence"])


if __name__ == "__main__":
    unittest.main()