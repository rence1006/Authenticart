"""
Fetches the storefront's homepage (and, if present, its policy pages) and
checks for structural trust signals: a real contact address, a return/refund
policy, a privacy policy, and telltale signs of copy-pasted template text.

This deliberately does NOT try to judge whether products are "real" —
that needs a curated reference catalog and is out of scope for the MVP.
Instead it looks for the *absence* of things every legitimate storefront
almost always has.
"""
import re
from typing import Optional
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup

CONTACT_KEYWORDS = ["contact us", "contact", "get in touch", "customer service"]
ADDRESS_PATTERN = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.\s]{3,40}\b(street|st\.|avenue|ave\.|road|rd\.|"
    r"boulevard|blvd\.|lane|ln\.|drive|dr\.|suite|floor)\b",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(r"(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}")
POLICY_LINK_KEYWORDS = {
    "return_policy": ["return", "refund", "exchange"],
    "privacy_policy": ["privacy"],
    "terms": ["terms of service", "terms & conditions", "terms and conditions"],
    "about": ["about us", "about"],
}
URGENCY_PHRASES = [
    "only 1 left", "hurry", "selling fast", "limited time", "% off today",
    "stock running out", "last chance", "flash sale",
]


class ScrapeResult:
    def __init__(self, domain: str):
        self.domain = domain
        self.final_url: Optional[str] = None
        self.reachable = False
        self.has_contact_info = False
        self.has_physical_address = False
        self.has_phone_number = False
        self.found_policies = []
        self.missing_policies = []
        self.urgency_phrase_count = 0
        self.error: Optional[str] = None

    def to_dict(self):
        return {
            "domain": self.domain,
            "final_url": self.final_url,
            "reachable": self.reachable,
            "has_contact_info": self.has_contact_info,
            "has_physical_address": self.has_physical_address,
            "has_phone_number": self.has_phone_number,
            "found_policies": self.found_policies,
            "missing_policies": self.missing_policies,
            "urgency_phrase_count": self.urgency_phrase_count,
            "error": self.error,
        }


async def scrape_storefront(url: str, timeout: float = 10.0) -> ScrapeResult:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    domain = urlparse(url).hostname or ""
    result = ScrapeResult(domain)

    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (AuthentiCartBot/1.0)"}
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            result.final_url = str(resp.url)
            html = resp.text
    except Exception as e:
        result.error = f"Could not fetch page: {e}"
        return result

    result.reachable = True
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    text_lower = text.lower()

    result.has_contact_info = any(kw in text_lower for kw in CONTACT_KEYWORDS)
    result.has_physical_address = bool(ADDRESS_PATTERN.search(text))
    result.has_phone_number = bool(PHONE_PATTERN.search(text))

    links = [a.get_text(strip=True).lower() + " " + (a.get("href") or "").lower()
             for a in soup.find_all("a")]
    all_link_text = " | ".join(links)

    for policy_name, keywords in POLICY_LINK_KEYWORDS.items():
        if any(kw in all_link_text for kw in keywords):
            result.found_policies.append(policy_name)
        else:
            result.missing_policies.append(policy_name)

    result.urgency_phrase_count = sum(text_lower.count(phrase) for phrase in URGENCY_PHRASES)

    return result
