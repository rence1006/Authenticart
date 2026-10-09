"""
Domain registration / age lookup using RDAP (the modern, free replacement
for WHOIS). No API key required.

rdap.org acts as a free bootstrap redirector: it looks at the TLD and
forwards the request to the correct registry's RDAP server, so we don't
need to maintain a table of registry endpoints ourselves.
"""
from datetime import datetime, timezone
from typing import Optional
import httpx
from dateutil import parser as dateparser

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"


class DomainAgeResult:
    def __init__(
        self,
        domain: str,
        registration_date: Optional[datetime],
        age_days: Optional[int],
        registrar: Optional[str],
        error: Optional[str] = None,
    ):
        self.domain = domain
        self.registration_date = registration_date
        self.age_days = age_days
        self.registrar = registrar
        self.error = error

    def to_dict(self):
        return {
            "domain": self.domain,
            "registration_date": self.registration_date.isoformat()
            if self.registration_date
            else None,
            "age_days": self.age_days,
            "registrar": self.registrar,
            "error": self.error,
        }


def _extract_registration_date(rdap_json: dict) -> Optional[datetime]:
    """RDAP responses list events with an 'eventAction'. We want the one
    marked 'registration'."""
    for event in rdap_json.get("events", []):
        if event.get("eventAction") == "registration":
            try:
                return dateparser.parse(event["eventDate"])
            except (ValueError, KeyError):
                continue
    return None


def _extract_registrar(rdap_json: dict) -> Optional[str]:
    for entity in rdap_json.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        return field[3]
            return entity.get("handle")
    return None


async def check_domain_age(domain: str) -> DomainAgeResult:
    domain = domain.lower().strip()
    url = RDAP_BOOTSTRAP.format(domain=domain)
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            resp = await client.get(url, headers={"Accept": "application/rdap+json"})
            if resp.status_code == 404:
                return DomainAgeResult(
                    domain, None, None, None,
                    error="No RDAP record found (domain may be unregistered or a "
                          "privacy-redacted TLD)."
                )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        return DomainAgeResult(domain, None, None, None, error=f"RDAP lookup failed: {e}")
    except ValueError:
        return DomainAgeResult(domain, None, None, None, error="RDAP response was not valid JSON.")
    except Exception as e:
        return DomainAgeResult(domain, None, None, None, error=f"Unexpected RDAP error: {e}")

    reg_date = _extract_registration_date(data)
    registrar = _extract_registrar(data)
    age_days = None
    if reg_date:
        if reg_date.tzinfo is None:
            reg_date = reg_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - reg_date).days

    return DomainAgeResult(domain, reg_date, age_days, registrar)
