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

from .whois_check import check_domain_age
from .ssl_check import check_ssl_certificate
from .scraper import scrape_storefront
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

    # Run all three checks concurrently — they're independent I/O calls.
    domain_age_task = check_domain_age(domain)
    scrape_task = scrape_storefront(payload.url)
    # ssl check is sync/blocking (uses the socket module), so run it in a thread
    loop = asyncio.get_running_loop()
    ssl_task = loop.run_in_executor(None, check_ssl_certificate, domain)

    # gather() returns results in the same order the awaitables were passed in
    domain_age_result, ssl_result, scrape_result = await asyncio.gather(
        domain_age_task, ssl_task, scrape_task
    )

    try:
        final_host = urlparse(scrape_result.final_url).hostname if scrape_result.final_url else domain
        brand = classify_domain(final_host or domain)
        brand["checked_host"] = final_host or domain
        verdict = compute_trust_score(domain_age_result, ssl_result, scrape_result, brand)
    except Exception as e:
        # HTTPException responses pass through CORS middleware, so the browser
        # shows the real message instead of a generic "Failed to fetch".
        raise HTTPException(status_code=500, detail=f"Scoring failed: {e}")

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
            "brand_check": brand,
        },
    }
