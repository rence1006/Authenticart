"""
Combines domain-age, SSL, and scraper signals into a single 0-100 Safety
Score, plus a human-readable list of reasons.

Scoring is additive-penalty: start at 100 and subtract points for each
red flag found. This keeps it easy to explain and easy to tune weights
later without rewriting the logic.

NOTE: language is deliberately phrased as risk/caution, not as a flat
accusation ("this is a scam") — see project notes on defamation exposure.
"""
from typing import List, Dict, Any, Optional
from .whois_check import DomainAgeResult
from .ssl_check import SSLResult
from .scraper import ScrapeResult

# Weights - tune these based on testing against known scam/legit sites
DOMAIN_AGE_VERY_NEW_DAYS = 30
DOMAIN_AGE_NEW_DAYS = 180
DOMAIN_AGE_ESTABLISHED_DAYS = 730  # 2 years


def score_domain_age(result: DomainAgeResult) -> tuple[int, List[str]]:
    reasons = []
    if result.error or result.age_days is None:
        return -10, [f"Caution: Could not verify domain registration date ({result.error or 'unknown'})."]

    age = result.age_days
    if age < DOMAIN_AGE_VERY_NEW_DAYS:
        return -40, [f"Caution: This domain was registered only {age} day(s) ago."]
    elif age < DOMAIN_AGE_NEW_DAYS:
        return -20, [f"Caution: This domain is relatively new ({age} days old)."]
    elif age < DOMAIN_AGE_ESTABLISHED_DAYS:
        return -5, [f"Note: Domain is {age} days old — not brand new, but not long-established either."]
    else:
        years = age // 365
        return 15, [f"Safe: Domain has been registered for {years}+ year(s)."]


def score_ssl(result: SSLResult) -> tuple[int, List[str]]:
    reasons = []
    if not result.valid:
        return -35, [f"Caution: Site does not have a valid SSL certificate ({result.error or 'unverified'})."]

    pts = 10
    reasons.append(f"Safe: Valid SSL certificate issued by {result.issuer}.")
    # A paid, OV, or EV certificate does not prove that a store is legitimate.
    # Keep certificate type informational instead of turning it into a trust bonus.
    if result.is_free_ca:
        reasons.append("Note: Uses a free certificate authority (common for both legitimate shops and scam sites).")
    else:
        reasons.append("Note: Certificate issuer type is not a legitimacy guarantee.")
    return pts, reasons


def score_scrape(result: ScrapeResult) -> tuple[int, List[str]]:
    reasons = []
    pts = 0

    if not result.reachable:
        return -20, [f"Caution: Storefront page could not be loaded ({result.error or 'unreachable'})."]

    if result.has_contact_info:
        pts += 5
    else:
        pts -= 15
        reasons.append("Caution: No contact information found on the site.")

    if result.has_physical_address:
        pts += 10
        reasons.append("Safe: A physical address was found on the site.")
    else:
        pts -= 10
        reasons.append("Caution: No physical address found — legitimate businesses usually list one.")

    if result.has_phone_number:
        pts += 5
    else:
        pts -= 5
        reasons.append("Caution: No phone number found.")

    if result.missing_policies:
        pts -= 5 * len(result.missing_policies)
        reasons.append(
            f"Caution: Missing pages: {', '.join(result.missing_policies)}."
        )
    if result.found_policies:
        pts += 5
        reasons.append(f"Safe: Found policy pages: {', '.join(result.found_policies)}.")

    if result.urgency_phrase_count >= 3:
        pts -= 15
        reasons.append(
            f"Caution: Page uses {result.urgency_phrase_count} urgency/pressure phrases "
            f"(e.g. 'only 1 left', 'hurry') — a common scam-store pattern."
        )
    elif result.urgency_phrase_count > 0:
        pts -= 5
        reasons.append(f"Note: Page uses {result.urgency_phrase_count} urgency phrase(s).")

    return pts, reasons


def compute_trust_score(
    domain_age: DomainAgeResult,
    ssl_result: SSLResult,
    scrape_result: ScrapeResult,
    brand: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base = 50  # neutral starting point
    total = base
    all_reasons: List[str] = []

    for scorer, result in (
        (score_domain_age, domain_age),
        (score_ssl, ssl_result),
        (score_scrape, scrape_result),
    ):
        pts, reasons = scorer(result)
        total += pts
        all_reasons.extend(reasons)

    # Brand identity is a bounded signal. It cannot make an impersonation
    # domain safe, and it cannot push an official domain above 90 without
    # hiding the underlying technical evidence.
    brand_status = (brand or {}).get("status", "unknown")
    brand_name = (brand or {}).get("brand")
    if brand_status == "trusted":
        total = max(total, 90)
        all_reasons.insert(0, f"Safe: Recognized official {brand_name} domain.")
        if (brand or {}).get("marketplace"):
            all_reasons.append(
                f"Note: {brand_name} is a legitimate marketplace, but individual sellers vary. "
                "Check seller ratings and pay only through the platform's own checkout."
            )
    elif brand_status == "lookalike":
        total = min(total, 15)
        all_reasons.insert(
            0,
            f"Caution: This domain imitates {brand_name} but is not an official {brand_name} domain.",
        )
    elif brand_status == "unverified_brand":
        total = min(total, 55)
        all_reasons.insert(
            0,
            f"Caution: This domain uses the {brand_name} name but is not on the official domain list.",
        )

    total = max(0, min(100, total))

    if total >= 75:
        label = "Likely Safe"
    elif total >= 45:
        label = "Use Caution"
    else:
        label = "High Risk"

    return {
        "score": total,
        "label": label,
        "reasons": all_reasons,
        "brand_status": brand_status,
    }
