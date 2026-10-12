# aureo-monitor
Anonymous external GET probe of a public storefront (cart, checkout redirect, TLS, protection-layer state) plus dead-man checks.
Runs on GitHub Actions every 15 min. No secrets in this repository; all configuration is in repository secrets.
Alerts: ntfy.sh topic (push) and a failed workflow run (GitHub e-mail). Recovery is published when all checks pass again.
