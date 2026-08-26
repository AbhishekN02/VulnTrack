import unittest

from scanner import validate_target
from risk_engine import score


class TestScannerGuardrail(unittest.TestCase):
    def test_localhost_allowed(self):
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_target("localhost"), "localhost")

    def test_public_ip_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("8.8.8.8")


class TestRiskEngine(unittest.TestCase):
    def test_medium_high_confidence_network_finding(self):
        finding = {
            "type": "SERVICE_EXPOSURE",
            "severity": "MEDIUM",
            "confidence": "HIGH",
        }
        self.assertEqual(score(finding), (60, "P2"))

    def test_low_high_confidence_network_finding(self):
        finding = {
            "type": "SERVICE_EXPOSURE",
            "severity": "LOW",
            "confidence": "HIGH",
        }
        self.assertEqual(score(finding), (30, "P3"))

    def test_info_filtered_finding(self):
        finding = {
            "type": "SERVICE_STATE",
            "severity": "INFO",
            "confidence": "HIGH",
        }
        self.assertEqual(score(finding), (6, "P4"))


if __name__ == "__main__":
    unittest.main()
