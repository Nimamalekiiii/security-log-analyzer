import unittest
from datetime import datetime

from analyzer import (
    calculate_risk_score,
    calculate_risk_level,
    detect_brute_force,
    detect_suspicious_login_pattern,
    detect_multiple_users,
    detect_account_enumeration
)


class TestSecurityAnalyzer(unittest.TestCase):

    def test_risk_score_low(self):
        score = calculate_risk_score(0)
        self.assertEqual(score, 0)

    def test_risk_score_brute_force(self):
        score = calculate_risk_score(5, brute_force=True)
        self.assertEqual(score, 75)

    def test_risk_level_low(self):
        self.assertEqual(calculate_risk_level(10), "LOW")

    def test_risk_level_medium(self):
        self.assertEqual(calculate_risk_level(30), "MEDIUM")

    def test_risk_level_high(self):
        self.assertEqual(calculate_risk_level(70), "HIGH")

    def test_brute_force_detection(self):
        timestamps = [
            datetime(2026, 9, 6, 10, 0, 0),
            datetime(2026, 9, 6, 10, 0, 5),
            datetime(2026, 9, 6, 10, 0, 10),
            datetime(2026, 9, 6, 10, 0, 15),
            datetime(2026, 9, 6, 10, 0, 20)
        ]

        self.assertTrue(detect_brute_force(timestamps))

    def test_brute_force_not_detected(self):
        timestamps = [
            datetime(2026, 9, 6, 10, 0, 0),
            datetime(2026, 9, 6, 10, 2, 0),
            datetime(2026, 9, 6, 10, 4, 0)
        ]

        self.assertFalse(detect_brute_force(timestamps))

    def test_suspicious_login_pattern(self):
        events = [
            {
                "type": "FAILED",
                "time": datetime(2026, 9, 6, 10, 0, 0),
                "user": "admin"
            },
            {
                "type": "FAILED",
                "time": datetime(2026, 9, 6, 10, 0, 5),
                "user": "admin"
            },
            {
                "type": "SUCCESS",
                "time": datetime(2026, 9, 6, 10, 0, 10),
                "user": "admin"
            }
        ]

        self.assertTrue(detect_suspicious_login_pattern(events))

    def test_multiple_users(self):
        users = {"admin", "root", "guest"}

        self.assertTrue(detect_multiple_users(users))

    def test_multiple_users_not_detected(self):
        users = {"admin", "root"}

        self.assertFalse(detect_multiple_users(users))

    def test_account_enumeration(self):
        events = [
            {
                "type": "FAILED",
                "time": datetime(2026, 9, 6, 10, 0, 0),
                "user": "admin"
            },
            {
                "type": "FAILED",
                "time": datetime(2026, 9, 6, 10, 0, 5),
                "user": "root"
            },
            {
                "type": "FAILED",
                "time": datetime(2026, 9, 6, 10, 0, 10),
                "user": "guest"
            }
        ]

        self.assertTrue(detect_account_enumeration(events))


if __name__ == "__main__":
    unittest.main()