# Domain & Hosting Configuration Guide

## Overview — the two domains you need
| Domain | Purpose | Example | Must be public? |
|---|---|---|---|
| Panel domain | YOUR admin dashboard only | panel.acme-test.com | Only reachable by YOU (tunnel/allowlist) |
| Mail domain | SENDER of lure emails | mail.acme-test.com | Needs SPF/DKIM/DMARC for inbox delivery |

Victim links always go to google.com/device — Google hosts them; you never
host the lure URL. Configure both domains in Settings → save → the Dashboard
"Active domains" card validates them live (green = you're browsing the panel
via the configured domain).

---

## Option A — VPS + nginx + Let's Encrypt (recommended)

1. Buy a domain (any registrar). Add an A record:
      panel.acme-test.com  →  A  →  <VPS-IP>
   (Optional subdomain for mail relay:) mail.acme-test.com → A → <VPS-IP>

2. On the VPS, run the panel HTTP-only:
      GPANEL_HTTP=1 GPANEL_USER=op1 GPANEL_PASS='S3cure!' python3 app.py
   (or via the systemd unit with GPANEL_HTTP=1 in /etc/gphish.env)

3. Install nginx + certbot:
      sudo apt install nginx certbot python3-certbot-nginx

4. /etc/nginx/sites-available/gphish:
      server {
          listen 443 ssl;
          server_name panel.acme-test.com;
          ssl_certificate     /etc/letsencrypt/live/panel.acme-test.com/fullchain.pem;
          ssl_certificate_key /etc/letsencrypt/live/panel.acme-test.com/privkey.pem;
          add_header X-Frame-Options DENY always;
          add_header X-Content-Type-Options nosniff always;
          # IP allowlist (strongly recommended):
          # allow <YOUR-IP>; deny all;
          location / {
              proxy_pass http://127.0.0.1:5443;
              proxy_set_header Host $host;
              proxy_set_header X-Forwarded-Host $host;      # ← powers the
              proxy_set_header X-Real-IP $remote_addr;      #   domain card
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
          }
      }
      server { listen 80; server_name panel.acme-test.com;
               return 301 https://$host$request_uri; }

5. Enable + get cert:
      sudo ln -s /etc/nginx/sites-available/gphish /etc/nginx/sites-enabled/
      sudo certbot --nginx -d panel.acme-test.com
      sudo nginx -t && sudo systemctl reload nginx

6. Firewall: open 80/443 only. KEEP 5443 CLOSED:
      sudo ufw allow 80,443/tcp && sudo ufw enable

7. DNS records for the MAIL domain (at your DNS provider):
      acme-test.com.        TXT  "v=spf1 mx a:mail.acme-test.com ~all"
      default._domainkey    TXT  (DKIM key from your relay/provider)
      _dmarc.acme-test.com. TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@acme-test.com"
   Verify: https://mxtoolbox.com/SuperTool.aspx (SPF/DKIM/DMARC lookups)

8. Dashboard check: browse https://panel.acme-test.com →
   "Active domains" card shows ✅ matches active.

## Option B — Cloudflare Tunnel (no open ports, hides VPS IP)

1. Domain's nameservers pointed at Cloudflare (free plan).
2. On the VPS:
      sudo curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
      sudo chmod +x /usr/local/bin/cloudflared
      cloudflared tunnel login
      cloudflared tunnel create gphish
      cloudflared tunnel route dns gphish panel.acme-test.com
      cloudflared tunnel run --url http://localhost:5443 gphish
   (add X-Forwarded-Host automatically — cloudflared sets it)
3. Panel runs GPANEL_HTTP=1; TLS terminates at Cloudflare's edge (valid cert,
   zero browser warnings); 5443 stays closed to the internet.
4. Cloudflare Access (optional, free ≤50 users): put an extra identity gate
   (email OTP / Google SSO) in front of the panel URL.
5. systemd: use gphish-cloudflared.service from earlier in this project.

## Option C — ngrok (quick, dev/testing)

      ngrok config add-authtoken <TOKEN>
      ngrok http https://localhost:5443 --domain=your-name.ngrok-free.app
   Random URLs change each restart on free tier; static domain needs a
   paid/reserved name. Fine for a test run; use A or B for engagements.

## Which domains to keep separate
- NEVER host the panel and send lure email from the same root domain as each
  other if avoidable — the dashboard card warns "NOT recommended" if they match.
- NEVER use the CLIENT'S real domain for sending — always your own registered
  test domain.
- Post-engagement: delete DNS records + revoke Cloudflare tunnel certs.s
