"""Unit tests for analyzer and risk calculation."""

import unittest
from core.analyzer import calculate_risk, empty_scan_data


class TestAnalyzer(unittest.TestCase):
    def test_calculate_risk_missing_headers_capped(self):
        scan_data = empty_scan_data()
        # Even if 6 headers are missing, header points should be capped and NOT make it CRITICAL
        scan_data["http_intel"] = [
            {
                "url": "http://example.com",
                "missing_security_headers": [
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Strict-Transport-Security",
                    "Referrer-Policy",
                    "Permissions-Policy",
                ],
            }
        ]
        risk = calculate_risk(scan_data)
        self.assertIn(risk["level"], {"LOW", "MEDIUM"})
        self.assertLessEqual(risk["score"], 3)

    def test_calculate_risk_critical_on_real_vulns(self):
        scan_data = empty_scan_data()
        scan_data["directories"] = [{"path": "/backup/backup.zip"}]
        scan_data["subdomains"] = [{"host": "admin.example.com"}]
        risk = calculate_risk(scan_data)
        self.assertEqual(risk["level"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
