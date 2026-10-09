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

## Run locally

AuthentiCart uses free public checks and does not require API keys for the included implementation.

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8002
```

Then serve the frontend in another terminal:

```bash
python -m http.server 5173 --directory frontend
```

Open `http://127.0.0.1:5173`. The local API is available at `http://127.0.0.1:8002`; interactive docs are available at `http://127.0.0.1:8002/docs` when public mode is disabled.

Example request:

```bash
curl -X POST http://127.0.0.1:8002/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Deploy on Vercel

The repository is configured for a free Vercel Hobby deployment. The FastAPI entry point is `api/index.py`; the browser client and logo are served from `public/` by the same deployment.

1. Import [the GitHub repository](https://github.com/rence1006/Authenticart) into Vercel.
2. Deploy from the repository root.
3. Set `AUTHENTICART_PUBLIC_MODE=1` in the Vercel project environment to keep Swagger, ReDoc, and the OpenAPI document disabled on the public site.

The current deployment is [authenticart-alpha.vercel.app](https://authenticart-alpha.vercel.app/). The public browser calls `/check` on that same origin, so there is no separate backend URL to configure in the frontend. The endpoint must remain reachable for the browser feature to work; do not place secrets or API keys in client files. Add authentication or rate limiting if the service later needs to be restricted.

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

## Possible next steps

- Browser extension that checks the active tab automatically.
- Result caching to avoid repeating checks for the same domain.
- A labeled dataset for evaluating and tuning scoring weights.
- Certificate Transparency lookup as an additional signal.
