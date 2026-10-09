# AuthentiCart — Explainable Store Risk Analyzer

AuthentiCart is a cybersecurity portfolio project that analyzes public storefront signals and explains a 0–100 risk score. It is a signal-based triage aid, not a verdict that a business is safe or fraudulent.

## How it works

Three independent checks run concurrently, and their results feed into a
weighted trust-score engine:

| Check | Module | What it looks at |
|---|---|---|
| Domain age | `app/whois_check.py` | RDAP registration date — free, no API key |
| TLS certificate | `app/ssl_check.py` | Certificate validation and issuer |
| Storefront content | `app/scraper.py` | Contact details, policy links, urgency-language patterns |

`app/scoring.py` combines all three into a final score + human-readable
bullet-point reasons (`compute_trust_score`).

`app/trusted_domains.py` adds a separate brand-identity signal. Exact official
domains are marked as trusted, lookalike domains are capped at 15, and brand
names on unverified domains are capped at 55. A trusted marketplace domain
still does not guarantee an individual seller or listing.

## Setup (free, no API keys needed)

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8002
```

The API is now running at `http://127.0.0.1:8002`.
Visit `http://127.0.0.1:8002/docs` for the interactive Swagger UI. The frontend in `frontend/index.html` points to port 8002; change `API_BASE` near the bottom of that file if your API uses another address.

For the frontend, serve the `frontend` directory with any static server, then open its URL. For example:

```bash
python -m http.server 5173 --directory frontend
```

Set `AUTHENTICART_CORS_ORIGINS` to a comma-separated list of allowed frontend origins before deploying, for example `https://your-site.example`. The local defaults allow `localhost:5173` and `127.0.0.1:5173`.

Example API request:

```bash
curl -X POST http://127.0.0.1:8002/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Example response

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "trust_score": 25,
  "label": "High Risk",
  "reasons": [
    "Safe: Domain has been registered for 31+ year(s).",
    "Safe: Valid SSL certificate issued by SSL Corporation.",
    "Note: Certificate issuer type is not a legitimacy guarantee.",
    "Caution: No physical address found — legitimate businesses usually list one."
  ],
  "details": { "...": "full raw data from each check" }
}
```

## Deploying for free

- **Vercel**: The repository includes `api/index.py` and `vercel.json` so the
  frontend can call the FastAPI app through the same origin at `/api/check`.
  Deploy the repository root, not only the `frontend` folder. Vercel's Hobby
  plan is suitable for a personal portfolio within its usage limits.
- The browser-visible `/api/check` route is not a secret. Same-origin routing
  hides the separate backend URL, but a public browser must still be able to
  call the endpoint. Do not put API keys in `frontend/index.html`; add
  authentication, rate limiting, or Vercel access protection if the endpoint
  must be restricted.
- Set `AUTHENTICART_PUBLIC_MODE=1` in Vercel if you want to disable the
  interactive `/docs`, `/redoc`, and `/openapi.json` routes. This reduces API
  discoverability, but it is not a replacement for authentication or rate
  limiting.
- **Separate backend**: You can instead deploy the FastAPI app to a Python
  host and set `API_BASE` to that HTTPS URL, then add the Vercel origin to
  `AUTHENTICART_CORS_ORIGINS`.

## Security and methodology notes

- A valid TLS certificate protects a connection; it does not establish that a store is honest. Certificate issuer type does not earn a trust bonus.
- The API accepts public HTTP(S) URLs only, rejects embedded credentials and literal private/reserved IP addresses, and limits URL length. Public deployment still needs DNS/IP resolution checks and redirect validation at the fetch layer to prevent SSRF via hostnames or redirects.
- CORS is restricted to local frontend origins by default. Set `AUTHENTICART_CORS_ORIGINS` to the deployed frontend origin(s) for production.
- Avoid sending sensitive URLs or private customer data to a public deployment. Requests trigger outbound RDAP, TLS, and HTTP checks against the submitted domain.

## Known limitations

- **RDAP/WHOIS privacy redaction**: some registries redact registrant info
  post-GDPR. Registration *date* is usually still available even when
  registrant *name* isn't — that's what we use.
- **Domain age is a signal, not proof**: legitimate businesses do launch new
  domains. It's weighted, not a hard pass/fail.
- **No live price-comparison engine**: detecting "suspicious price drops"
  needs either historical pricing data or a reference catalog, which is out
  of scope for this MVP. The urgency-language detector (`URGENCY_PHRASES`
  in `scraper.py`) is a lightweight proxy for the same scam pattern.
- **JS-heavy storefronts**: the scraper uses plain HTTP + BeautifulSoup, so
  sites that render content entirely via JavaScript may return incomplete
  signals. Swapping in Playwright would fix this at the cost of being
  slower and heavier — a reasonable "next steps" item.

## Next steps / stretch goals

- Browser extension (`manifest.json` + content script) that reads the
  current tab's URL and calls `/check` automatically.
- Cache results (e.g. Redis or even a SQLite table) so repeated checks on
  the same domain within 24h don't re-run all three checks.
- Curate a small labeled dataset of known scam vs. legit stores to
  backtest and tune the scoring weights in `app/scoring.py`.
- Certificate Transparency log lookup (crt.sh, also free) as a fourth
  signal — shows the *first* time a cert was ever issued for a domain,
  which is harder to fake than the current cert's dates alone.
