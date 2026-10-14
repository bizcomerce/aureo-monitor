# aureo-monitor
Anonymous external GET probe of a public storefront (cart, checkout redirect, TLS, protection-layer state) plus dead-man checks.
Runs on GitHub Actions every 15 min. No secrets in this repository; all configuration is in repository secrets.
Alerts: ntfy.sh topic (push) and a failed workflow run (GitHub e-mail). Recovery is published when all checks pass again.

## Alert classes (since incident #154, 2026-10-14)
Each failed check records a safe fingerprint of the response that failed it: HTTP code, `Server` token, origin evidence (LiteSpeed/PHP/X-Aureo headers or WordPress markers), redirect class (cart / same-host / external / none), size, sha256_8 of the body and TTFB. It records no path, query, Location value or body. A failing run also logs the runner's public IP.
- **SALES/WALL ALERT** (urgent): a failure answered by the shop's origin, a proxy 5xx, no response, or TLS. Unchanged.
- **MONITOR FAILURE - STORE STATUS UNVERIFIED** (urgent): responses that are neither provably the shop nor a recognised challenge.
- **MONITOR ACCESS BLOCKED - STORE STATUS UNVERIFIED** (high): only hosting-challenge responses (`Server: openresty` answering 200/403/429 itself, with no origin evidence).

Every class alerts immediately. If one run has failures of several classes, the most severe class sets the alert. The B0 and Shop checks pass only on an origin response. TLS verifies the certificate chain, hostname and days left, and is independent of application availability.
Manual `drill=dry` runs every check against production and publishes nothing (exit 0). Use it to check a change before it reaches `main`.
