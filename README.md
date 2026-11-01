# aureo-monitor
Anonymous external GET probe of a public storefront (cart, checkout redirect, TLS, protection-layer state) plus dead-man checks.
Runs on GitHub Actions every 15 min. No secrets in this repository; all configuration is in repository secrets.
Alerts: ntfy.sh topic (push) and, for a newly announced confirmed or ambiguous incident only, a failed workflow run (GitHub e-mail). Recovery is published when all checks pass again.

## Alert classes (since incident #154, 2026-10-14)
Each failed check records a safe fingerprint of the response that failed it: HTTP code, `Server` token, origin evidence (LiteSpeed/PHP/X-Aureo headers or WordPress markers), redirect class (cart / same-host / external / none), size, sha256_8 of the body and TTFB. It records no path, query, Location value or body. A failing run also logs the runner's public IP.
- **SALES/WALL ALERT** (urgent): a failure answered by the shop's origin, a proxy 5xx, no response, or TLS. Unchanged.
- **MONITOR FAILURE - STORE STATUS UNVERIFIED** (urgent): responses that are neither provably the shop nor a recognised challenge.
- **INCONCLUSIVE - STORE STATUS UNVERIFIED** (silent, since 2026-11-01): only hosting-challenge responses (`Server: openresty` answering 200/403/429 itself, with no origin evidence). The check could not be made and the shop was not reached. This is neither a shop failure nor a pass. The run succeeds (no "Run failed" mail) but shows a `::warning` annotation and `result: INCONCLUSIVE - STORE STATUS UNVERIFIED` in its summary, never `ALL PASS`.

If one run has failures of several classes, the most severe class sets the alert. The B0 and Shop checks pass only on an origin response. TLS verifies the certificate chain, hostname and days left, and is independent of application availability.

## Grouping (since 2026-11-01)
- **Confirmed / ambiguous alerts** push once, urgent, and fail that run. The same incident is not pushed again for 60 min; the runs in between succeed with `::error ... ONGOING incident` and `result: ONGOING`, so there is no mail every 15 min. After 60 min it is announced again. A different failing set is a new incident. `RECOVERED` is pushed when all checks pass.
- **Inconclusive runs** publish one silent (priority `min`) `INCONCLUSIVE` marker on the alert topic. Consecutive markers (each within 40 min of the previous) form an episode. After 40 min of an unbroken episode ONE high-priority `UNVERIFIED` push says the shop has been unverifiable for that long (repeated at most every 3 h). A healthy run publishes a silent `CLEARED`. A real failure, `RECOVERED` or a gap longer than 40 min ends the episode. The on-host collector and dead-man cover an actual outage independently.
- Topic state is read from the ntfy alert topic (6 h). If ntfy cannot be read, every run behaves as the first run of an episode.

## Diagnostics for a challenge or unknown response
Only for a failing check whose response is not provably the shop: `xdiag` (runner-seen peer IP, HTTP version, connect and TLS times, response header NAMES, `Content-Type`, `Date`, cookie NAMES, a sanitised `<title>` and boolean body markers `imunify360,captcha,aureo_fv,reload,script`) and, once per such run, `control` (two GETs of `/robots.txt`, one with the monitor UA and one with a browser-shaped UA: the same result for both means an IP block, a difference means a per-UA rule). No header value other than `Content-Type`/`Date`, no cookie value, no body, no secret path is ever written. Everything is an allow-listed character set with a length cap. The lines go to the run log and the step summary.
Manual `drill=dry` runs every check against production and publishes nothing (exit 0). Use it to check a change before it reaches `main`.
