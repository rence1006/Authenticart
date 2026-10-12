"""
Fetches the storefront's homepage (and, if present, its policy pages) and
checks for structural trust signals: a real contact address, a return/refund
policy, a privacy policy, and telltale signs of copy-pasted template text.

This deliberately does NOT try to judge whether products are "real" —
that needs a curated reference catalog and is out of scope for the MVP.
Instead it looks for the *absence* of things every legitimate storefront
almost always has.
"""
import asyncio
import re
import ipaddress
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
import tldextract

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
PAYMENT_RED_FLAG_PATTERNS = [
    r"\bpersonal\s+gcash\b",
    r"\bsend\s+(?:to|via)\s+gcash\b",
    r"\bgcash\s+(?:number|account)\b",
    r"\bbank\s+transfer\s+only\b",
    r"\b(?:wire|bank)\s+transfer\b",
    r"\bdeposit\s+(?:to|into)\s+(?:my|our)\s+bank\b",
]
FORM_PAYMENT_TERMS = ("card", "credit", "debit", "payment", "checkout", "gcash", "bank transfer")
SOCIAL_HOSTS = ("facebook.com", "instagram.com", "tiktok.com", "youtube.com", "x.com", "twitter.com")
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 2 * 1024 * 1024


def _validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public HTTP(S) URLs are allowed.")
    host = parsed.hostname.rstrip(".")
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)]
        except OSError as exc:
            raise ValueError(f"Could not resolve storefront host: {exc}") from exc
    if any(
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_reserved or address.is_multicast or address.is_unspecified
        for address in addresses
    ):
        raise ValueError("Private, local, and reserved hosts are not allowed.")


class ScrapeResult:
    def __init__(self, domain: str):
        self.domain = domain
        self.final_url: Optional[str] = None
        self.redirect_count = 0
        self.redirect_hosts = []
        self.reachable = False
        self.inspectable = False
        self.has_contact_info = False
        self.has_physical_address = False
        self.has_phone_number = False
        self.found_policies = []
        self.missing_policies = []
        self.urgency_phrase_count = 0
        self.has_login_form = False
        self.has_payment_form = False
        self.external_form_actions = []
        self.payment_red_flags = []
        self.business_registration_mentions = []
        self.social_links_found = []
        self.error: Optional[str] = None

    def to_dict(self):
        return {
            "domain": self.domain,
            "status": "verified" if self.inspectable else "unknown",
            "final_url": self.final_url,
            "redirect_count": self.redirect_count,
            "redirect_hosts": self.redirect_hosts,
            "reachable": self.reachable,
            "inspectable": self.inspectable,
            "has_contact_info": self.has_contact_info,
            "has_physical_address": self.has_physical_address,
            "has_phone_number": self.has_phone_number,
            "found_policies": self.found_policies,
            "missing_policies": self.missing_policies,
            "urgency_phrase_count": self.urgency_phrase_count,
            "has_login_form": self.has_login_form,
            "has_payment_form": self.has_payment_form,
            "external_form_actions": self.external_form_actions,
            "payment_red_flags": self.payment_red_flags,
            "business_registration_mentions": self.business_registration_mentions,
            "social_links_found": self.social_links_found,
            "error": self.error,
        }


async def scrape_storefront(url: str, timeout: float = 10.0) -> ScrapeResult:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    domain = urlparse(url).hostname or ""
    result = ScrapeResult(domain)

    try:
        await asyncio.to_thread(_validate_public_url, url)
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (AuthentiCartBot/1.0)"}
        ) as client:
            current_url = url
            body = bytearray()
            while True:
                await asyncio.to_thread(_validate_public_url, current_url)
                async with client.stream("GET", current_url) as resp:
                    if 300 <= resp.status_code < 400:
                        location = resp.headers.get("location")
                        if not location:
                            raise ValueError("Redirect response did not include a destination.")
                        if result.redirect_count >= MAX_REDIRECTS:
                            raise ValueError(f"Redirect limit ({MAX_REDIRECTS}) reached.")
                        result.redirect_hosts.append(urlparse(current_url).hostname or "")
                        result.redirect_count += 1
                        current_url = urljoin(current_url, location)
                        await asyncio.to_thread(_validate_public_url, current_url)
                        continue
                    resp.raise_for_status()
                    result.final_url = str(resp.url)
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_BODY_BYTES:
                            raise ValueError(f"Response exceeds the {MAX_BODY_BYTES // (1024 * 1024)} MB limit.")
                    break
            html = bytes(body).decode(resp.encoding or "utf-8", errors="replace")
    except Exception as e:
        result.error = f"Could not fetch page: {e}"
        return result

    result.reachable = True
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    text_lower = text.lower()

    # A successful HTTP response can still be a JS shell, bot challenge, or
    # consent wall. Do not turn unavailable content into a list of red flags.
    challenge_markers = (
        "checking your browser", "verify you are human", "captcha",
        "access denied", "enable javascript", "just a moment",
        "cf-chl", "bot verification",
    )
    if len(text) < 80 or any(marker in text_lower for marker in challenge_markers):
        result.error = "page is JavaScript-rendered or bot-challenged"
        return result

    result.inspectable = True

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

    result.payment_red_flags = [
        pattern for pattern in PAYMENT_RED_FLAG_PATTERNS
        if re.search(pattern, text_lower)
    ]
    result.business_registration_mentions = [
        name for name in ("DTI", "SEC")
        if re.search(rf"\b{name.lower()}\b", text_lower)
    ]
    result.social_links_found = sorted({
        host for link in soup.find_all("a", href=True)
        for host in [urlparse(link.get("href", "")).hostname or ""]
        if any(host == social or host.endswith(f".{social}") for social in SOCIAL_HOSTS)
    })

    page_registered_domain = _EXTRACT(result.final_url or url).registered_domain.lower()
    for form in soup.find_all("form"):
        form_text = " ".join(form.get_text(" ", strip=True).lower().split())
        fields = " ".join(
            " ".join(str(value) for value in values)
            for element in form.find_all(["input", "select", "textarea"])
            for values in [element.attrs.values()]
        ).lower()
        form_context = f"{form_text} {fields}"
        if form.find("input", attrs={"type": re.compile(r"password", re.I)}) or any(
            term in form_context for term in ("log in", "login", "sign in", "password")
        ):
            result.has_login_form = True
        if any(term in form_context for term in FORM_PAYMENT_TERMS) or form.find(
            "input", attrs={"name": re.compile(r"(card|cvv|cvc|expiry|payment)", re.I)}
        ):
            result.has_payment_form = True

        action = urljoin(result.final_url or url, form.get("action") or "")
        action_host = urlparse(action).hostname or ""
        action_registered_domain = _EXTRACT(action_host).registered_domain.lower()
        if action_registered_domain and page_registered_domain and action_registered_domain != page_registered_domain:
            result.external_form_actions.append(action_host)

    return result
