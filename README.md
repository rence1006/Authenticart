# AuthentiCart — Explainable Store Trust Analyzer

[![Live demo](https://img.shields.io/badge/live_demo-Vercel-black?logo=vercel)](https://authenticart-alpha.vercel.app/)

**Live application:** [authenticart-alpha.vercel.app](https://authenticart-alpha.vercel.app/)

AuthentiCart is a cybersecurity portfolio project that helps shoppers triage an unfamiliar online store before purchasing. A user submits a public store URL and receives a 0–100 trust score, a plain-language verdict, and the signals that influenced it. The result is an indicator for investigation, not a guarantee that a business or seller is safe.

## System overview

The browser client and FastAPI service are deployed together on Vercel. The frontend sends a URL to the same-origin `/check` endpoint. The API runs three independent checks concurrently, then combines their results with brand-domain verification:

```text
Store URL
   │
   ├── Domain age / RDAP       app/whois_check.py
   ├── TLS certificate         app/ssl_check.py
   ├── Storefront signals      app/scraper.py
   └── Brand-domain identity   app/trusted_domains.py
             │
             ▼
       app/scoring.py
             │
             ▼
  Score + verdict + evidence
```

### Signals used

| Signal | What it checks |
|---|---|
| Domain age | Registration data from RDAP, when available |
| TLS certificate | Whether HTTPS is valid and who issued the certificate |
| Storefront content | Contact details, address, phone number, policies, and pressure-selling language |
| Trusted brands | Whether the hostname exactly matches a curated official domain or looks like a brand impersonation |

## Trusted-brand protection

The brand check helps prevent legitimate marketplaces from being incorrectly flagged solely because they are large shared platforms such as Shopee or Lazada:

- Official domains such as `shopee.ph` and `lazada.com.ph` receive a trusted brand signal and a high score floor.
- Lookalikes such as `sh0pee.ph`, `shoppee.ph`, and `shopee.evil.com` are classified as impersonation and capped at a very low score.
- Brand names on unverified domains such as `shopee.xyz` are capped below the safe range until the domain is confirmed.
- A trusted marketplace is not a guarantee for every seller or listing. The result reminds shoppers to check seller ratings and pay through the platform's checkout.

Only domains in the curated `BRANDS` list are treated as official. Add a domain there only after confirming it belongs to the brand.

Example request:

```bash
curl -X POST http://127.0.0.1:8002/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Security and methodology notes

- A valid TLS certificate protects a connection; it does not prove that a store is honest.
- The API accepts public HTTP(S) URLs, rejects embedded credentials and literal private or reserved IP addresses, and limits URL length.
- Public deployments should add DNS and redirect validation at the fetch layer before handling untrusted traffic at scale.
- CORS is restricted by configuration. Set `AUTHENTICART_CORS_ORIGINS` when using a separate frontend origin.
- Do not submit sensitive URLs or private customer data to a public instance.

## Known limitations

- RDAP can be unavailable or privacy-redacted, so domain age may be unknown.
- Domain age and TLS are signals, not proof of legitimacy.
- Plain HTTP scraping can miss content rendered entirely by JavaScript.
- The system does not score individual marketplace sellers or compare live prices.
