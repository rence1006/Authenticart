"""Certificate Transparency lookup through the public crt.sh JSON endpoint."""
from datetime import datetime, timezone
from typing import Optional

import httpx
from dateutil import parser as dateparser


class CTResult:
    def __init__(
        self,
        domain: str,
        oldest_certificate: Optional[datetime] = None,
        certificate_count: int = 0,
        error: Optional[str] = None,
    ):
        self.domain = domain
        self.oldest_certificate = oldest_certificate
        self.certificate_count = certificate_count
        self.error = error

    @property
    def age_days(self) -> Optional[int]:
        if not self.oldest_certificate:
            return None
        created = self.oldest_certificate
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).days

    def to_dict(self):
        return {
            "domain": self.domain,
            "status": "verified" if self.oldest_certificate else "unknown",
            "oldest_certificate": self.oldest_certificate.isoformat() if self.oldest_certificate else None,
            "certificate_age_days": self.age_days,
            "certificate_count": self.certificate_count,
            "error": self.error,
        }


async def check_certificate_transparency(domain: str, timeout: float = 5.0) -> CTResult:
    domain = domain.lower().strip()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json", "User-Agent": "AuthentiCartBot/1.0"},
            )
            response.raise_for_status()
            if len(response.content) > 2 * 1024 * 1024:
                return CTResult(domain, error="Certificate Transparency response exceeded the size limit.")
            rows = response.json()
    except Exception as exc:
        return CTResult(domain, error=f"Certificate Transparency lookup failed: {exc}")

    if not isinstance(rows, list):
        return CTResult(domain, error="Certificate Transparency response was not a list.")

    dates = []
    for row in rows:
        try:
            value = row.get("not_before")
            if value:
                dates.append(dateparser.parse(value))
        except (AttributeError, TypeError, ValueError, OverflowError):
            continue
    if not dates:
        return CTResult(domain, certificate_count=len(rows), error="No certificate dates were published.")
    return CTResult(domain, min(dates), len(rows))
