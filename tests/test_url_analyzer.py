"""
test_url_analyzer.py
---------------------
Tests for url_analyzer.py using Python's built-in unittest.

Run with:
    python -m unittest tests.test_url_analyzer -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from url_analyzer import analyze_url


class TestAnalyzeUrl(unittest.TestCase):

    def test_normal_https_url_has_few_flags(self):
        result = analyze_url("https://www.wikipedia.org/wiki/Security")
        self.assertTrue(result["valid"])
        self.assertFalse(result["indicators"]["not_https"])
        self.assertFalse(result["indicators"]["ip_address_host"])

    def test_suspicious_url_detects_multiple_flags(self):
        result = analyze_url("http://192.168.1.1/secure-login-verify-account@evil.com")
        self.assertTrue(result["valid"])
        self.assertTrue(result["indicators"]["not_https"])
        self.assertTrue(result["indicators"]["at_symbol"])

    def test_ip_address_host_detected(self):
        result = analyze_url("http://203.0.113.5/login")
        self.assertTrue(result["indicators"]["ip_address_host"])

    def test_excessive_subdomains_detected(self):
        result = analyze_url("https://secure.login.verify.account.mybank.example.com")
        self.assertTrue(result["indicators"]["excessive_subdomains"])

    def test_suspicious_tld_detected(self):
        result = analyze_url("http://free-prize-claim.xyz")
        self.assertTrue(result["indicators"]["suspicious_tld"])

    def test_bare_domain_gets_normalized(self):
        result = analyze_url("example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["parsed"]["host"], "example.com")

    def test_empty_input_is_invalid(self):
        result = analyze_url("")
        self.assertFalse(result["valid"])

    def test_malformed_url_is_invalid(self):
        result = analyze_url("http://")
        self.assertFalse(result["valid"])

    def test_extremely_long_url_is_rejected(self):
        result = analyze_url("http://example.com/" + "a" * 3000)
        self.assertFalse(result["valid"])

    def test_many_hyphens_detected(self):
        result = analyze_url("http://paypal-secure-account-login-verify-now.com")
        self.assertTrue(result["indicators"]["many_hyphens"])


if __name__ == "__main__":
    unittest.main()