# Security Policy

## Reporting a vulnerability

Please do not publish exploit details in a public issue. Report suspected vulnerabilities privately to the repository owner through the contact method on the GitHub profile, including reproduction steps, affected endpoint, and impact.

## Scope

AuthentiCart accepts public URLs and fetches them server-side. The application applies URL scheme validation, private and loopback host rejection, DNS checks, redirect limits, response-size limits, and response security headers. These controls reduce SSRF risk but are not a guarantee of safety for an internet-facing deployment.

Do not submit credentials, private URLs, customer data, or payment information to a public instance.
