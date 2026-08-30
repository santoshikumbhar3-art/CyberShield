"""
test_analyzer.py
-----------------
Tests for analyzer.py using Python's built-in unittest — no external
test framework (like pytest) is used, per the zero-dependency rule.

Run with:
    python -m unittest tests.test_analyzer -v
or run all tests with:
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import analyze_message, extract_urls


class TestAnalyzeMessage(unittest.TestCase):

    def test_normal_message_has_no_indicators(self):
        result = analyze_message("Hey, are we still on for lunch tomorrow?")
        self.assertTrue(result["valid"])
        self.assertFalse(any(result["indicators"].values()))

    def test_phishing_message_detects_multiple_indicators(self):
        message = (
            "Your bank account will be blocked today. Verify your account "
            "immediately by clicking this link: http://secure-bank-login.xyz"
        )
        result = analyze_message(message)
        self.assertTrue(result["valid"])
        self.assertTrue(result["indicators"]["urgency"])
        self.assertTrue(result["indicators"]["credential_request"])
        self.assertTrue(len(result["urls_found"]) == 1)

    def test_urgent_scam_message(self):
        message = "URGENT: Act now, your account will be suspended within 24 hours!"
        result = analyze_message(message)
        self.assertTrue(result["indicators"]["urgency"])

    def test_credential_theft_message(self):
        message = "Please confirm your password and verify your identity to continue."
        result = analyze_message(message)
        self.assertTrue(result["indicators"]["credential_request"])

    def test_financial_scam_message(self):
        message = "Congratulations you've won! Pay a small fee to claim your prize now."
        result = analyze_message(message)
        self.assertTrue(result["indicators"]["unrealistic_reward"])
        self.assertTrue(result["indicators"]["financial_request"])

    def test_empty_input_is_invalid(self):
        result = analyze_message("")
        self.assertFalse(result["valid"])
        self.assertIsNotNone(result["error"])

    def test_whitespace_only_input_is_invalid(self):
        result = analyze_message("     ")
        self.assertFalse(result["valid"])

    def test_none_input_is_invalid(self):
        result = analyze_message(None)
        self.assertFalse(result["valid"])

    def test_extremely_long_input_is_rejected(self):
        message = "a" * 6000
        result = analyze_message(message)
        self.assertFalse(result["valid"])

    def test_extract_urls_finds_links_in_text(self):
        message = "Check this out: https://example.com/path and www.test.com too"
        urls = extract_urls(message)
        self.assertEqual(len(urls), 2)


if __name__ == "__main__":
    unittest.main()