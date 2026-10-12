import unittest

from app.scoring import compute_trust_score, score_scrape
from app.scraper import ScrapeResult
from app.ssl_check import SSLResult
from app.whois_check import DomainAgeResult


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.age = DomainAgeResult("example.com", None, None, None, error="lookup unavailable")
        self.ssl = SSLResult("example.com", valid=False, error="timeout")
        self.scrape = ScrapeResult("example.com")

    def test_unknown_checks_do_not_add_red_penalties(self):
        verdict = compute_trust_score(self.age, self.ssl, self.scrape)
        self.assertEqual(verdict["score"], 50)
        self.assertTrue(any("Storefront checks skipped" in reason for reason in verdict["reasons"]))
        self.assertEqual(verdict["signal_points"][0]["points"], 0)
        self.assertEqual(verdict["signal_points"][1]["points"], 0)

    def test_trusted_brand_override_is_explicit(self):
        verdict = compute_trust_score(
            self.age,
            self.ssl,
            self.scrape,
            {"status": "trusted", "brand": "Shopee", "marketplace": True},
        )
        self.assertEqual(verdict["score"], 90)
        self.assertTrue(any("Trusted-brand override" in reason for reason in verdict["reasons"]))
        self.assertEqual(verdict["signal_points"][-1]["signal"], "Trusted-brand override")

    def test_inspectable_storefront_scores_confirmed_signals(self):
        result = ScrapeResult("shop.example")
        result.reachable = True
        result.inspectable = True
        result.has_contact_info = True
        result.has_physical_address = True
        result.has_phone_number = True
        result.found_policies = ["privacy_policy"]
        result.missing_policies = []
        points, reasons = score_scrape(result)
        self.assertEqual(points, 25)
        self.assertTrue(any("Contact information found" in reason for reason in reasons))


if __name__ == "__main__":
    unittest.main()
