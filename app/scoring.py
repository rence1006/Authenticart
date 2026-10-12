"""
Combines domain-age, SSL, and scraper signals into a single 0-100 Safety
Score, plus a human-readable list of reasons.

Scoring starts at a neutral 50 and adds or subtracts bounded signal points.
Unknown checks contribute zero points, so missing evidence does not masquerade
as a confirmed risk.

NOTE: language is deliberately phrased as risk/caution, not as a flat
accusation ("this is a scam") — see project notes on defamation exposure.
"""
from typing import List, Dict, Any, Optional
from .whois_check import DomainAgeResult
from .ssl_check import SSLResult
from .scraper import ScrapeResult
from .ct_check import CTResult
import tldextract

# Weights - tune these based on testing against known scam/legit sites
DOMAIN_AGE_VERY_NEW_DAYS = 30
DOMAIN_AGE_NEW_DAYS = 180
DOMAIN_AGE_ESTABLISHED_DAYS = 730  # 2 years
RISKY_TLDS = {"shop", "xyz", "top"}
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def score_domain_age(result: DomainAgeResult) -> tuple[int, List[str]]:
    if result.error or result.age_days is None:
        return 0, [f"Note: Domain age could not be verified ({result.error or 'unknown'}; 0 points)."]

    age = result.age_days
    if age < DOMAIN_AGE_VERY_NEW_DAYS:
        return -40, [f"Caution: Domain registered {age} day(s) ago (-40 points)."]
    elif age < DOMAIN_AGE_NEW_DAYS:
        return -20, [f"Caution: Domain is relatively new ({age} days; -20 points)."]
    elif age < DOMAIN_AGE_ESTABLISHED_DAYS:
        return -5, [f"Note: Domain is {age} days old (-5 points)."]
    else:
        years = age // 365
        return 15, [f"Safe: Domain registered for {years}+ year(s) (+15 points)."]


def score_ssl(result: SSLResult) -> tuple[int, List[str]]:
    if not result.valid:
        if result.error and result.error.startswith("Certificate verification failed"):
            return -35, [f"Caution: TLS certificate validation failed (-35 points; {result.error})."]
        return 0, [f"Note: TLS certificate could not be verified ({result.error or 'unknown error'}; 0 points)."]

    pts = 10
    reasons = [f"Safe: Valid TLS certificate (+10 points; issuer: {result.issuer or 'unknown'})."]
    # A paid, OV, or EV certificate does not prove that a store is legitimate.
    # Keep certificate type informational instead of turning it into a trust bonus.
    if result.is_free_ca:
        reasons.append("Note: Uses a free certificate authority (0 points; common across the web).")
    else:
        reasons.append("Note: Certificate issuer type is not a legitimacy guarantee (0 points).")
    return pts, reasons


def score_tld(domain: str) -> tuple[int, List[str]]:
    suffix = _EXTRACT(domain).suffix.lower()
    if suffix in RISKY_TLDS:
        return -5, [f"Note: Uses .{suffix}, a higher-risk storefront TLD (-5 points)."]
    return 0, [f"Note: Storefront TLD .{suffix or 'unknown'} carries no additional weight (0 points)."]


def score_certificate_transparency(result: CTResult) -> tuple[int, List[str]]:
    if result.age_days is None:
        return 0, [f"Note: Certificate age could not be verified ({result.error or 'unknown'}; 0 points)."]
    if result.age_days < 30:
        return -10, [f"Caution: Oldest publicly logged certificate is {result.age_days} day(s) old (-10 points)."]
    if result.age_days < 180:
        return -3, [f"Note: Oldest publicly logged certificate is {result.age_days} days old (-3 points)."]
    return 2, [f"Note: Certificate has been publicly logged for {result.age_days} days (+2 points)."]


def score_scrape(result: ScrapeResult) -> tuple[int, List[str]]:
    reasons = []
    pts = 0

    if not result.reachable or not result.inspectable:
        detail = result.error or "page content could not be inspected"
        return 0, [f"Note: Storefront checks skipped ({detail}; 0 points)."]

    if result.has_contact_info:
        pts += 5
        reasons.append("Safe: Contact information found (+5 points).")
    else:
        pts -= 15
        reasons.append("Caution: No contact information found (-15 points).")

    if result.has_physical_address:
        pts += 10
        reasons.append("Safe: Physical address found (+10 points).")
    else:
        pts -= 10
        reasons.append("Caution: No physical address found (-10 points).")

    if result.has_phone_number:
        pts += 5
        reasons.append("Safe: Phone number found (+5 points).")
    else:
        pts -= 5
        reasons.append("Caution: No phone number found (-5 points).")

    if result.missing_policies:
        pts -= 5 * len(result.missing_policies)
        reasons.append(
            f"Caution: Missing pages: {', '.join(result.missing_policies)} (-{5 * len(result.missing_policies)} points)."
        )
    if result.found_policies:
        pts += 5
        reasons.append(f"Safe: Policy pages found: {', '.join(result.found_policies)} (+5 points).")

    if result.urgency_phrase_count >= 3:
        pts -= 15
        reasons.append(
            f"Caution: Page uses {result.urgency_phrase_count} urgency/pressure phrases "
            f"(e.g. 'only 1 left', 'hurry'; -15 points)."
        )
    elif result.urgency_phrase_count > 0:
        pts -= 5
        reasons.append(f"Note: Page uses {result.urgency_phrase_count} urgency phrase(s) (-5 points).")

    if result.redirect_count >= 2:
        pts -= 5
        reasons.append(f"Note: Storefront followed {result.redirect_count} redirects (-5 points).")

    if result.external_form_actions:
        pts -= 20
        hosts = ", ".join(sorted(set(result.external_form_actions)))
        reasons.append(f"Caution: A form submits to another domain ({hosts}; -20 points).")

    if result.payment_red_flags:
        pts -= 15
        reasons.append(f"Caution: Payment instructions include personal or transfer-only wording (-15 points).")

    if result.has_login_form or result.has_payment_form:
        form_types = []
        if result.has_login_form:
            form_types.append("login")
        if result.has_payment_form:
            form_types.append("payment")
        reasons.append(f"Note: Found {' and '.join(form_types)} form(s); review where data is submitted (0 points).")

    if result.business_registration_mentions:
        names = "/".join(result.business_registration_mentions)
        pts += 2
        reasons.append(f"Note: Page mentions {names} registration (+2 points; mention only, not verified).")
    else:
        reasons.append("Note: No DTI or SEC registration mention found (0 points; absence is inconclusive).")

    if result.social_links_found:
        pts += 1
        reasons.append(f"Note: Social links found (+1 point; links were not independently verified).")
    else:
        reasons.append("Note: No social links found (0 points; absence is inconclusive).")

    return pts, reasons


def compute_trust_score(
    domain_age: DomainAgeResult,
    ssl_result: SSLResult,
    scrape_result: ScrapeResult,
    brand: Optional[Dict[str, Any]] = None,
    ct_result: Optional[CTResult] = None,
) -> Dict[str, Any]:
    base = 50  # neutral starting point
    total = base
    all_reasons: List[str] = []

    signal_points = []
    for name, scorer, result in (
        ("Domain age", score_domain_age, domain_age),
        ("TLS", score_ssl, ssl_result),
        ("Storefront", score_scrape, scrape_result),
    ):
        pts, reasons = scorer(result)
        total += pts
        signal_points.append({"signal": name, "points": pts})
        all_reasons.extend(reasons)

    tld_points, tld_reasons = score_tld(domain_age.domain)
    total += tld_points
    signal_points.append({"signal": "TLD", "points": tld_points})
    all_reasons.extend(tld_reasons)

    if ct_result is not None:
        ct_points, ct_reasons = score_certificate_transparency(ct_result)
        total += ct_points
        signal_points.append({"signal": "Certificate Transparency", "points": ct_points})
        all_reasons.extend(ct_reasons)

    # Brand identity is a bounded signal. It cannot make an impersonation
    # domain safe, and it cannot push an official domain above 90 without
    # hiding the underlying technical evidence.
    brand_status = (brand or {}).get("status", "unknown")
    brand_name = (brand or {}).get("brand")
    if brand_status == "trusted":
        raw_total = total
        total = max(total, 90)
        override = total - raw_total
        signal_points.append({"signal": "Trusted-brand override", "points": override})
        all_reasons.insert(0, f"Safe: Trusted-brand override +{override} points (score floor: 90).")
        all_reasons.insert(1, f"Safe: Recognized official {brand_name} domain (+0 points).")
        if (brand or {}).get("marketplace"):
            all_reasons.append(
                f"Note: {brand_name} is a legitimate marketplace, but individual sellers vary. "
                "Check seller ratings and pay only through the platform's own checkout."
                " (0 points)."
            )
    elif brand_status == "lookalike":
        raw_total = total
        total = min(total, 15)
        cap_adjustment = total - raw_total
        signal_points.append({"signal": "Brand identity cap", "points": cap_adjustment})
        all_reasons.insert(
            0,
            f"Caution: This domain imitates {brand_name} but is not an official {brand_name} domain ({cap_adjustment} points).",
        )
    elif brand_status == "unverified_brand":
        raw_total = total
        total = min(total, 55)
        cap_adjustment = total - raw_total
        signal_points.append({"signal": "Unverified brand cap", "points": cap_adjustment})
        all_reasons.insert(
            0,
            f"Caution: This domain uses the {brand_name} name but is not on the official domain list ({cap_adjustment} points).",
        )
    else:
        signal_points.append({"signal": "Brand identity", "points": 0})

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
        "signal_points": signal_points,
        "base_score": base,
        "brand_status": brand_status,
    }
