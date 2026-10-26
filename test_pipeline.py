
import unittest

from pipeline import parse_log, detect_attacks
from app import app


class TestLogLens(unittest.TestCase):

    def test_parse_valid_log(self):
        line = (
            '192.168.1.10 - - [26/Oct/2026:18:30:00 +0530] '
            '"GET /home HTTP/1.1" 200 512'
        )
        result = parse_log(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "192.168.1.10")
        self.assertEqual(result["status"], 200)

    def test_invalid_log(self):
        result = parse_log("this is not a valid log")
        self.assertIsNone(result)

    def test_detect_xss(self):
        result = detect_attacks("/search?q=<script>alert(1)</script>")
        self.assertIn("xss", result)

    def test_detect_directory_traversal(self):
        result = detect_attacks("/../../etc/passwd")
        self.assertIn("directory_traversal", result)

    def test_normal_path(self):
        result = detect_attacks("/home")
        self.assertEqual(result, [])

    def test_home_api(self):
        client = app.test_client()
        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "running")

    def test_summary_api(self):
        client = app.test_client()
        response = client.get("/api/summary")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertIn("total_logs", data)
        self.assertIn("suspicious_ip_count", data)
        self.assertIn("attack_counts", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
