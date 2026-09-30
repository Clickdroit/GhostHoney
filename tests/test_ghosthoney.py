import unittest
from ghosthoney.storage import HoneypotStorage
from ghosthoney.geoip import enrich_ip

class TestGhostHoney(unittest.TestCase):
    def setUp(self):
        self.storage = HoneypotStorage(":memory:")

    def tearDown(self):
        self.storage.close()

    def test_record_and_retrieve_attack(self):
        attack_data = {
            "protocol": "SSH",
            "source_ip": "1.2.3.4",
            "source_port": 50123,
            "username": "root",
            "password": "password123",
            "country": "Testland",
            "city": "Testcity"
        }
        attack_id = self.storage.record_attack(attack_data)
        self.assertGreater(attack_id, 0)

        recent = self.storage.get_recent_attacks(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["username"], "root")
        self.assertEqual(recent[0]["source_ip"], "1.2.3.4")

        stats = self.storage.get_overview_stats()
        self.assertEqual(stats["total_attacks"], 1)
        self.assertEqual(stats["unique_ips"], 1)

    def test_geoip_enrichment(self):
        lan = enrich_ip("192.168.1.50")
        self.assertEqual(lan["country_code"], "LO")

        external = enrich_ip("8.8.8.8")
        self.assertIn("country", external)
        self.assertIn("latitude", external)

if __name__ == "__main__":
    unittest.main()
