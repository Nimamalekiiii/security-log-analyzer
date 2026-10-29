import unittest

from web_analyzer import (
    classify_request,
    detect_path_scanning,
    calculate_risk_score,
    calculate_risk_level,
)


class TestWebAnalyzer(unittest.TestCase):

    def test_detect_sql_injection(self):
        hits = classify_request("/sqli/?id=1' UNION SELECT user,password FROM users-- -", "")
        self.assertIn("sql_injection", hits)

    def test_detect_sql_injection_or(self):
        hits = classify_request("/sqli/?id=1' OR '1'='1", "")
        self.assertIn("sql_injection", hits)

    def test_detect_xss_encoded(self):
        hits = classify_request("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "")
        self.assertIn("xss", hits)

    def test_detect_path_traversal(self):
        hits = classify_request("/?page=../../../../etc/passwd", "")
        self.assertIn("path_traversal", hits)

    def test_detect_scanner_user_agent(self):
        hits = classify_request("/", "sqlmap/1.7")
        self.assertIn("scanner", hits)

    def test_clean_request(self):
        hits = classify_request("/images/logo.png", "Mozilla/5.0")
        self.assertEqual(hits, set())

    def test_path_scanning(self):
        entry = {"not_found": 12, "paths": set()}
        self.assertTrue(detect_path_scanning(entry))

    def test_no_path_scanning(self):
        entry = {"not_found": 2, "paths": {"/a", "/b"}}
        self.assertFalse(detect_path_scanning(entry))

    def test_risk_score_sqli_high(self):
        entry = {
            "attacks": {"sql_injection": 3, "xss": 0, "path_traversal": 1, "scanner": 1},
            "not_found": 12, "paths": set(),
        }
        self.assertEqual(calculate_risk_level(calculate_risk_score(entry)), "HIGH")

    def test_risk_score_clean_low(self):
        entry = {
            "attacks": {"sql_injection": 0, "xss": 0, "path_traversal": 0, "scanner": 0},
            "not_found": 0, "paths": {"/"},
        }
        self.assertEqual(calculate_risk_level(calculate_risk_score(entry)), "LOW")


if __name__ == "__main__":
    unittest.main()
