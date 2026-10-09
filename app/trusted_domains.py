"""Known-brand domain matching and impersonation detection.

Brand identity is kept separate from storefront risk. An official marketplace
domain can still contain risky sellers, so callers should display that caveat.
"""
from typing import Any, Dict, List, Optional


BRANDS: Dict[str, Dict[str, Any]] = {
    "shopee": {"name": "Shopee", "marketplace": True, "domains": [
        "shopee.ph", "shopee.com", "shopee.sg", "shopee.com.my",
        "shopee.co.id", "shopee.vn", "shopee.co.th", "shopee.tw",
    ]},
    "lazada": {"name": "Lazada", "marketplace": True, "domains": [
        "lazada.com.ph", "lazada.com", "lazada.sg", "lazada.com.my",
        "lazada.co.id", "lazada.vn", "lazada.co.th",
    ]},
    "zalora": {"name": "Zalora", "marketplace": False, "domains": [
        "zalora.com.ph", "zalora.com", "zalora.sg", "zalora.com.my",
    ]},
    "carousell": {"name": "Carousell", "marketplace": True, "domains": [
        "carousell.ph", "carousell.com", "carousell.sg", "carousell.com.my",
    ]},
    "gcash": {"name": "GCash", "marketplace": False, "domains": ["gcash.com"]},
    "amazon": {"name": "Amazon", "marketplace": True, "domains": [
        "amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.sg",
        "amazon.in", "amazon.com.au", "amazon.co.jp",
    ]},
    "ebay": {"name": "eBay", "marketplace": True, "domains": ["ebay.com"]},
    "aliexpress": {"name": "AliExpress", "marketplace": True, "domains": ["aliexpress.com"]},
    "alibaba": {"name": "Alibaba", "marketplace": True, "domains": ["alibaba.com"]},
    "temu": {"name": "Temu", "marketplace": True, "domains": ["temu.com"]},
    "shein": {"name": "Shein", "marketplace": False, "domains": ["shein.com"]},
    "tiktok": {"name": "TikTok", "marketplace": True, "domains": ["tiktok.com"]},
    "etsy": {"name": "Etsy", "marketplace": True, "domains": ["etsy.com"]},
    "nike": {"name": "Nike", "marketplace": False, "domains": ["nike.com"]},
    "adidas": {"name": "Adidas", "marketplace": False, "domains": ["adidas.com"]},
}

# Trust only reviewed subdomains beyond each exact official domain. Add entries
# here after verification; do not automatically trust every possible subdomain.
ALLOWED_SUBDOMAINS = {
    "seller.shopee.ph",
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
SECOND_LEVELS = {"com", "co", "net", "org", "gov", "edu", "ac"}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (char_a != char_b),
            ))
        previous = current
    return previous[-1]


def _clean_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _official_match(host: str, domains: List[str]) -> Optional[str]:
    """Return an exact official domain match."""
    for domain in domains:
        domain = domain.lower().rstrip(".")
        if host == domain:
            return domain
    return None


def _registrable_index(labels: List[str]) -> int:
    # Covers common structures such as shopee.com.ph and shopee.co.uk without
    # adding a heavyweight public-suffix dependency to the MVP.
    if len(labels) >= 3 and labels[-2] in SECOND_LEVELS and len(labels[-1]) == 2:
        return len(labels) - 3
    return len(labels) - 2


def _imitates(label: str, brand: str) -> bool:
    variants = {label, label.translate(LEET)}
    for variant in variants:
        tokens = variant.split("-")
        if brand in tokens and variant != brand:
            return True
        if len(brand) >= 5 and brand in variant and variant != brand:
            return True
        if len(brand) >= 6:
            for token in [variant] + tokens:
                if token != brand and abs(len(token) - len(brand)) <= 1 and _levenshtein(token, brand) <= 1:
                    return True
        if variant == brand and label != brand:
            return True
    return False


def classify_domain(host: str) -> Dict[str, Any]:
    """Classify a hostname as trusted, unverified, lookalike, or unknown."""
    host = _clean_host(host)
    labels = host.split(".") if host else []

    for key, info in BRANDS.items():
        matched_domain = _official_match(host, info["domains"])
        if not matched_domain:
            matched_domain = next(
                (allowed for allowed in ALLOWED_SUBDOMAINS if host == allowed),
                None,
            )
        if matched_domain:
            brand_key = next(
                (brand_key for brand_key, brand_info in BRANDS.items()
                 if brand_info["name"] == info["name"]),
                key,
            )
            # An explicitly approved host must still be associated with the
            # correct brand; approved entries are maintained by the project.
            if matched_domain in ALLOWED_SUBDOMAINS and brand_key not in matched_domain.split("."):
                continue
            return {
                "status": "trusted",
                "brand": info["name"],
                "marketplace": info["marketplace"],
                "matched_domain": matched_domain,
            }

    if len(labels) < 2:
        return {"status": "unknown", "brand": None, "marketplace": False, "matched_domain": None}

    registrable_idx = _registrable_index(labels)
    for key, info in BRANDS.items():
        for index, label in enumerate(labels[:-1]):
            if label == key:
                status = "unverified_brand" if index == registrable_idx else "lookalike"
                return {
                    "status": status,
                    "brand": info["name"],
                    "marketplace": info["marketplace"],
                    "matched_domain": None,
                }
            if _imitates(label, key):
                return {
                    "status": "lookalike",
                    "brand": info["name"],
                    "marketplace": info["marketplace"],
                    "matched_domain": None,
                }

    return {"status": "unknown", "brand": None, "marketplace": False, "matched_domain": None}
