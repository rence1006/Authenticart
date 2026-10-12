"""
AuthentiCart API — paste a store URL, get back a Safety Score.

Run locally:
    pip install -r requirements.txt
    uvicorn app.main:app --reload

Then open http://127.0.0.1:8000/docs for the interactive API explorer,
or POST to /check with {"url": "https://example.com"}.
"""
import asyncio
import ipaddress
import os
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .whois_check import DomainAgeResult, check_domain_age
from .ssl_check import SSLResult, check_ssl_certificate
from .scraper import ScrapeResult, scrape_storefront
from .ct_check import CTResult, check_certificate_transparency
from .scoring import compute_trust_score
from .trusted_domains import classify_domain

public_mode = os.getenv("AUTHENTICART_PUBLIC_MODE", "0") == "1" or os.getenv("VERCEL") == "1"
app = FastAPI(
    title="AuthentiCart API",
    description="Checks an e-commerce URL's trustworthiness: domain age, SSL, and site content signals.",
    version="0.1.0",
    docs_url=None if public_mode else "/docs",
    redoc_url=None if public_mode else "/redoc",
    openapi_url=None if public_mode else "/openapi.json",
)

configured_origins = os.getenv(
    "AUTHENTICART_CORS_ORIGINS",
    "http://127.0.0.1:5173,http://localhost:5173",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in configured_origins.split(",") if origin.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:8002 http://localhost:8002"
    )
    return response

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PUBLIC_DIR = PROJECT_ROOT / "public"
PUBLIC_ASSETS_DIR = PUBLIC_DIR / "assets"

# Serve the browser client from the same FastAPI function on Vercel. This keeps
# the deployed UI and API same-origin, so no backend URL or CORS exception is
# exposed to visitors.
if PUBLIC_ASSETS_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=PUBLIC_ASSETS_DIR), name="assets")


class CheckRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048, examples=["https://example-shop.com"])


def _extract_domain(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise ValueError("Use a public HTTP(S) store URL without embedded credentials.")
    if not host or " " in host or "." not in host:
        raise ValueError("That doesn't look like a valid website address (e.g. example.com).")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast):
        raise ValueError("Private, local, and reserved IP addresses are not allowed.")
    return host.lower().rstrip(".")


@app.get("/")
async def root():
    index_file = PUBLIC_DIR / "index.html"
    if index_file.is_file():
        return FileResponse(index_file, media_type="text/html")
    return {"status": "ok", "service": "AuthentiCart API", "try": "POST /check with {\"url\": \"...\"}"}


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok", "service": "AuthentiCart API"}


@app.post("/check")
async def check_store(payload: CheckRequest):
    try:
        domain = _extract_domain(payload.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Run all independent checks concurrently so one slow provider does not
    # block the others.
    domain_age_task = asyncio.wait_for(check_domain_age(domain), timeout=12.0)
    scrape_task = asyncio.wait_for(scrape_storefront(payload.url), timeout=12.0)
    ct_task = asyncio.wait_for(check_certificate_transparency(domain), timeout=7.0)
    # ssl check is sync/blocking (uses the socket module), so run it in a thread
    loop = asyncio.get_running_loop()
    ssl_task = asyncio.wait_for(
        loop.run_in_executor(None, check_ssl_certificate, domain),
        timeout=10.0,
    )

    # gather() returns results in the same order the awaitables were passed in
    domain_age_result, ssl_result, scrape_result, ct_result = await asyncio.gather(
        domain_age_task, ssl_task, scrape_task, ct_task, return_exceptions=True
    )

    # A single provider timeout must not turn an otherwise useful check into a
    # 500. Preserve the failed signal as an explicit unknown result.
    if isinstance(domain_age_result, Exception):
        domain_age_result = DomainAgeResult(
            domain, None, None, None,
            error=f"Domain age check failed: {domain_age_result}",
        )
    if isinstance(ssl_result, Exception):
        ssl_result = SSLResult(
            domain, valid=False,
            error=f"TLS check failed: {ssl_result}",
        )
    if isinstance(scrape_result, Exception):
        scrape_error = scrape_result
        scrape_result = ScrapeResult(domain)
        scrape_result.error = f"Storefront check failed: {scrape_error}"
    if isinstance(ct_result, Exception):
        ct_result = CTResult(domain, error=f"Certificate Transparency check failed: {ct_result}")

    final_host = urlparse(scrape_result.final_url).hostname if scrape_result.final_url else domain
    brand = classify_domain(final_host or domain)
    brand["checked_host"] = final_host or domain
    verdict = compute_trust_score(domain_age_result, ssl_result, scrape_result, brand, ct_result)

    return {
        "url": payload.url,
        "domain": domain,
        "trust_score": verdict["score"],
        "label": verdict["label"],
        "reasons": verdict["reasons"],
        "details": {
            "domain_age": domain_age_result.to_dict(),
            "ssl": ssl_result.to_dict(),
            "content_signals": scrape_result.to_dict(),
            "certificate_transparency": ct_result.to_dict(),
            "brand_check": brand,
        },
    }
