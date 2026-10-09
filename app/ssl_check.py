"""
Pulls the live TLS certificate for a domain and reports its issuer,
validity window, and whether it's a "cheap"/free CA (Let's Encrypt, ZeroSSL)
vs. an organization-validated (OV) or extended-validation (EV) cert.

Free CAs aren't inherently suspicious (most legit small businesses use
Let's Encrypt too) — but the ABSENCE of a valid cert, or a cert that
doesn't match the hostname, is a strong red flag.
"""
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from dateutil import parser as dateparser

FREE_CA_KEYWORDS = ["let's encrypt", "lets encrypt", "zerossl", "cloudflare"]


class SSLResult:
    def __init__(
        self,
        domain: str,
        valid: bool,
        issuer: Optional[str] = None,
        not_before: Optional[datetime] = None,
        not_after: Optional[datetime] = None,
        is_free_ca: Optional[bool] = None,
        error: Optional[str] = None,
    ):
        self.domain = domain
        self.valid = valid
        self.issuer = issuer
        self.not_before = not_before
        self.not_after = not_after
        self.is_free_ca = is_free_ca
        self.error = error

    def to_dict(self):
        return {
            "domain": self.domain,
            "valid": self.valid,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "is_free_ca": self.is_free_ca,
            "error": self.error,
        }


def check_ssl_certificate(domain: str, timeout: float = 8.0) -> SSLResult:
    domain = domain.lower().strip()
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return SSLResult(domain, valid=False, error=f"Certificate verification failed: {e}")
    except ssl.SSLError as e:
        return SSLResult(domain, valid=False, error=f"TLS error: {e}")
    except OSError as e:
        # Covers timeouts, DNS failures, refused/reset connections, unreachable networks
        return SSLResult(domain, valid=False, error=f"Could not connect on port 443: {e}")
    except Exception as e:
        return SSLResult(domain, valid=False, error=f"Unexpected SSL check error: {e}")

    try:
        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer_parts.get("organizationName") or issuer_parts.get("commonName", "Unknown")
        not_before = dateparser.parse(cert["notBefore"]).replace(tzinfo=timezone.utc)
        not_after = dateparser.parse(cert["notAfter"]).replace(tzinfo=timezone.utc)
    except Exception as e:
        return SSLResult(domain, valid=False, error=f"Could not parse certificate: {e}")

    is_free_ca = any(kw in issuer_name.lower() for kw in FREE_CA_KEYWORDS)

    return SSLResult(
        domain=domain,
        valid=True,
        issuer=issuer_name,
        not_before=not_before,
        not_after=not_after,
        is_free_ca=is_free_ca,
    )
