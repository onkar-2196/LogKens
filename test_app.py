
import unittest
import app as log_app


class TestFlaskApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        log_app.app.config["TESTING"] = True
        cls.client = log_app.app.test_client()

    def test_home_api(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertEqual(data["project"], "LogLens")
        self.assertEqual(data["status"], "running")

    def test_dashboard_page(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Security Log Analysis Dashboard",
            response.data
        )

    def test_logs_api(self):
        response = self.client.get("/api/logs")

        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_summary_api(self):
        response = self.client.get("/api/summary")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertIn("total_logs", data)
        self.assertIn("suspicious_ip_count", data)
        self.assertIn("attack_counts", data)

        self.assertIsInstance(data["attack_counts"], dict)


if __name__ == "__main__":
    unittest.main()
