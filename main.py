import os, json, time, uuid
from datetime import datetime, timezone
from flask import Flask, request, redirect, jsonify, render_template_string, make_response, url_for
import jwt
from jwcrypto import jwk

# ===== Load Private JWK Securely (file > env) =====
JWK_PRIVATE_FILE = os.getenv("JWK_PRIVATE_FILE")  # e.g. /run/secrets/jwk_private.json
JWK_PRIVATE_JSON = os.getenv("JWK_PRIVATE_JSON")  # fallback (less secure)

def _load_private_jwk_json():
    if JWK_PRIVATE_FILE and os.path.exists(JWK_PRIVATE_FILE):
        with open(JWK_PRIVATE_FILE, "r", encoding="utf-8") as f:
            return f.read()
    if JWK_PRIVATE_JSON:
        return JWK_PRIVATE_JSON
    raise RuntimeError("No private JWK provided. Set JWK_PRIVATE_FILE or JWK_PRIVATE_JSON.")

PRIV_JWK = jwk.JWK.from_json(_load_private_jwk_json())
if "kid" not in json.loads(PRIV_JWK.export_public()):
    PRIV_JWK["kid"] = uuid.uuid4().hex
KID = json.loads(PRIV_JWK.export_public())["kid"]

# ===== Basic Config =====
ALG = "PS512"
ISSUER = "JWT API Simulation"
AUDIENCE = "JWT API Simulation"
LEEWAY_SECONDS = 2
COOKIE_NAME = "session_jwt"
COOKIE_EXP = "jwt_exp"  # Non-sensitive, only stores exp seconds for countdown

def private_pem():
    return PRIV_JWK.export_to_pem(private_key=True, password=None)

def public_pem():
    return PRIV_JWK.export_to_pem(private_key=False)

def public_jwk_obj():
    pub = json.loads(PRIV_JWK.export_public())
    pub.setdefault("use", "sig")
    pub.setdefault("alg", ALG)
    return pub

# ===== Flask =====
app = Flask(__name__)

INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>JWT Issuer</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
:root{
  --bg:#0b1220;
  --card:#11182a;
  --muted:#8592a6;
  --text:#e6eefc;
  --accent:#6ea8ff;
  --accent-2:#8b5cf6;
  --ring: rgba(110,168,255,.55);
  --pill:#1c2337;
  --border:#1f2a44;
}
@media (prefers-color-scheme: light){
  :root{
    --bg:#f6f8fc;
    --card:#ffffff;
    --muted:#556070;
    --text:#0f172a;
    --accent:#2563eb;
    --accent-2:#7c3aed;
    --ring: rgba(37,99,235,.35);
    --pill:#f1f5f9;
    --border:#e5e7eb;
  }
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
  background:
    radial-gradient(1200px 600px at -10% -10%, rgba(139,92,246,.15), transparent 60%),
    radial-gradient(1200px 600px at 110% -10%, rgba(37,99,235,.12), transparent 60%),
    var(--bg);
  color:var(--text);
}
.container{max-width:980px; margin:48px auto; padding:0 20px}
.header{
  border:1px solid var(--border);
  background: linear-gradient(135deg, rgba(110,168,255,.14), rgba(139,92,246,.12)) , var(--card);
  border-radius:20px; padding:24px 20px; box-shadow: 0 10px 30px rgba(0,0,0,.12);
}
.h-row{display:flex; flex-wrap:wrap; align-items:center; gap:12px; justify-content:space-between}
.h-title{
  display:flex; align-items:center; gap:10px; font-weight:800; letter-spacing:.2px;
  font-size: clamp(20px, 2.6vw, 28px);
}
.h-sub{color:var(--muted); font-size:14px}
.badges{display:flex; flex-wrap:wrap; gap:8px; margin-top:10px}
.pill{
  background:var(--pill); color:var(--muted);
  padding:6px 10px; border-radius:999px; font-size:13px; border:1px solid var(--border)
}
.card{
  margin-top:18px; border:1px solid var(--border); background:var(--card);
  border-radius:18px; padding:22px; box-shadow: 0 12px 30px rgba(0,0,0,.10);
}
.form-row{display:flex; gap:10px; align-items:center; flex-wrap:wrap}
.input{
  appearance:none; width:min(420px, 100%);
  padding:12px 14px; border-radius:12px; border:1px solid var(--border);
  background:linear-gradient(180deg, rgba(255,255,255,.06), transparent), var(--card);
  color:var(--text); font-size:16px; outline:none; transition:.18s ease;
}
.input::placeholder{color:var(--muted)}
.input:focus{ border-color:var(--accent); box-shadow: 0 0 0 4px var(--ring) }
.btn{
  appearance:none; border:1px solid var(--border); border-radius:12px;
  padding:12px 16px; font-weight:700; cursor:pointer; transition:.18s ease;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  color:white;
}
.btn:hover{ filter:brightness(1.05); transform: translateY(-1px); box-shadow:0 10px 24px rgba(0,0,0,.18)}
.links{margin-top:14px; font-size:14px}
a{color:var(--accent); text-decoration:none}
a:hover{text-decoration:underline}
.small{font-size:12.5px; color:var(--muted)}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="h-row">
        <div>
          <div class="h-title">🔐 Issue a 30-second JWT</div>
          <div class="h-sub">Enter a UID and we’ll mint a short-lived token and store it in an <b>HttpOnly</b> cookie.</div>
        </div>
      </div>
      <div class="badges">
        <span class="pill">alg={{alg}}</span>
        <span class="pill">kid={{kid}}</span>
        <span class="pill">iss={{iss}}</span>
        <span class="pill">aud={{aud}}</span>
      </div>
    </div>

    <div class="card">
      <form method="POST" action="/issue" class="form-row">
        <input class="input" name="uid" placeholder="user-123" required autocomplete="off" />
        <button class="btn" type="submit">Issue</button>
      </form>
      <div class="links">
        JWKS: <a href="/.well-known/jwks.json">/.well-known/jwks.json</a>
        <div class="small" style="margin-top:8px">Tip: After issuing, you’ll be redirected to the demo page to call the protected API.</div>
      </div>
    </div>
  </div>
</body>
</html>
"""

DEMO_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>JWT API Simulation</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
:root{
  --bg:#0b1220;
  --card:#11182a;
  --muted:#8592a6;
  --text:#e6eefc;
  --accent:#6ea8ff;
  --accent-2:#8b5cf6;
  --ring: rgba(110,168,255,.55);
  --ok:#10b981;
  --ok-bg:#064e3b;
  --err:#ef4444;
  --err-bg:#3b0c0c;
  --pill:#1c2337;
  --code:#0a0f1e;
  --code-text:#d6e7ff;
  --border:#1f2a44;
}
@media (prefers-color-scheme: light){
  :root{
    --bg:#f6f8fc;
    --card:#ffffff;
    --muted:#556070;
    --text:#0f172a;
    --accent:#2563eb;
    --accent-2:#7c3aed;
    --ring: rgba(37,99,235,.35);
    --ok:#059669;
    --ok-bg:#e7f7f2;
    --err:#dc2626;
    --err-bg:#fee2e2;
    --pill:#f1f5f9;
    --code:#0b1021;
    --code-text:#d6e7ff;
    --border:#e5e7eb;
  }
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
  background:
    radial-gradient(1200px 600px at -10% -10%, rgba(139,92,246,.15), transparent 60%),
    radial-gradient(1200px 600px at 110% -10%, rgba(37,99,235,.12), transparent 60%),
    var(--bg);
  color:var(--text);
}
.container{max-width:980px; margin:48px auto; padding:0 20px}
.header{
  border:1px solid var(--border);
  background: linear-gradient(135deg, rgba(110,168,255,.14), rgba(139,92,246,.12)) , var(--card);
  border-radius:20px; padding:22px 20px; box-shadow: 0 10px 30px rgba(0,0,0,.12);
}
.h-row{display:flex; flex-wrap:wrap; align-items:center; gap:12px}
.h-title{
  display:flex; align-items:center; gap:12px; font-weight:800; letter-spacing:.2px;
  font-size: clamp(20px, 2.6vw, 28px);
}
.badges{display:flex; flex-wrap:wrap; gap:8px; margin-top:8px}
.pill{
  background:var(--pill); color:var(--muted);
  padding:6px 10px; border-radius:999px; font-size:13px; border:1px solid var(--border)
}
.card{
  margin-top:18px; border:1px solid var(--border); background:var(--card);
  border-radius:18px; padding:20px; box-shadow: 0 12px 30px rgba(0,0,0,.10);
}
.actions{display:flex; gap:10px; align-items:center; flex-wrap:wrap}
.btn{
  appearance:none; border:1px solid var(--border); border-radius:12px;
  padding:10px 14px; font-weight:600; cursor:pointer; transition:.18s ease;
  background:linear-gradient(180deg, rgba(255,255,255,.06), transparent), var(--card);
  color:var(--text);
}
.btn:hover{ transform: translateY(-1px); box-shadow:0 8px 20px rgba(0,0,0,.18); border-color:var(--accent) }
.btn.primary{
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  border: none; color:white;
}
.btn.primary:hover{ filter:brightness(1.05)}
.btn:disabled{opacity:.6; cursor:not-allowed; transform:none; box-shadow:none}
.count{
  display:flex; align-items:center; gap:6px; color:var(--muted); font-weight:600
}
.kbd{
  border:1px solid var(--border); background:var(--pill); border-bottom-width:3px; padding:2px 6px; border-radius:8px; font-size:12px
}
.note{
  margin:12px 0 18px; padding:10px 12px; border-radius:10px; font-size:14px; color:var(--muted);
  background: linear-gradient(180deg, rgba(255,255,255,.04), transparent), var(--pill); border:1px solid var(--border)
}
.err{
  color: var(--err);
  background: linear-gradient(180deg, rgba(255,255,255,.04), transparent), var(--err-bg);
  border: 1px solid color-mix(in oklab, var(--err) 40%, transparent);
  padding:10px 12px; border-radius:10px; margin:10px 0; display:none
}
.err.show{display:block}
.status-ok{
  color:var(--ok); background:var(--ok-bg); border:1px solid color-mix(in oklab, var(--ok) 40%, transparent);
  padding:8px 10px; border-radius:10px; display:none; margin:10px 0
}
.status-ok.show{display:block}
pre{
  white-space:pre-wrap; background:var(--code); color:var(--code-text);
  padding:14px; border-radius:14px; border:1px solid rgba(255,255,255,.06); font-size:13.5px;
}
.meta{display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top:10px}
.spinner{
  width:16px; height:16px; border:3px solid rgba(255,255,255,.25); border-top-color:white; border-radius:50%;
  animation: spin .8s linear infinite; display:none
}
.btn.loading .spinner{display:inline-block}
.btn .txt{display:inline-block; transform: translateY(0); transition: .18s ease}
.btn.loading .txt{opacity:.85}
@keyframes spin{to{transform:rotate(360deg)}}
hr{height:1px; border:none; background:var(--border); margin:16px 0}
.small{font-size:12.5px; color:var(--muted)}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="h-row">
        <div class="h-title">🔐 JWT API Simulation</div>
        <div class="count">⏳ Countdown <span id="cd" class="kbd">--</span>s</div>
      </div>
      <div class="badges">
        <span class="pill">alg={{alg}}</span>
        <span class="pill">kid={{kid}}</span>
        <span class="pill">iss={{iss}}</span>
        <span class="pill">aud={{aud}}</span>
      </div>
    </div>

    <div class="card">
      <div class="note">This page never stores JWT in URL, LocalStorage, SessionStorage, or JS variables. JWT is kept only in an <b>HttpOnly</b> cookie.</div>
      <div class="actions">
        <button id="btn" class="btn primary"><span class="spinner" aria-hidden="true"></span> <span class="txt">Call Protected API (/api/ping)</span></button>
        <button id="reset" class="btn" onclick="location.href='/reset'" style="display:none">Reset</button>
        <span class="small">Tip: Re-issue token if it expires.</span>
      </div>

      <div id="expired" class="err">❌ JWT invaild or missing (401). Click <b>Reset</b> to re-issue.</div>
      <div id="waf403" class="err">🛡️ Blocked by WAF (403). Likely missing/invalid JWT at the edge.</div>
      <div id="rate429" class="err">🚦 Rate limited by WAF (429). Too many requests. Please slow down and try again later.</div>
      <div id="genericErr" class="err">⚠️ Network error. If a WAF sits in front, ensure a valid JWT cookie and try again.</div>
      <div id="ok" class="status-ok">✅ Request succeeded.</div>

      <h3 style="margin-top:18px">Server Validation Result</h3>
      <pre id="out">Not called yet</pre>

      <div class="meta">
        <span class="small">Need a new token? Use the <b>Reset</b> button and issue again.</span>
      </div>
    </div>
  </div>

<script>
const exp = Number({{exp}});  // injected by server (non-sensitive)
const out = document.getElementById("out");
const cd = document.getElementById("cd");
const expiredBox = document.getElementById("expired");
const waf403Box = document.getElementById("waf403");
const rate429Box = document.getElementById("rate429");
const genericErr = document.getElementById("genericErr");
const okBox = document.getElementById("ok");
const resetBtn = document.getElementById("reset");
const btn = document.getElementById("btn");

function show(el){ el.classList.add("show"); resetBtn.style.display = "inline-block"; }
function hideAll(){
  [expiredBox, waf403Box, rate429Box, genericErr, okBox].forEach(e=>e.classList.remove("show"));
}
function setLoading(v){
  if(v){ btn.classList.add("loading"); btn.disabled = true; }
  else { btn.classList.remove("loading"); btn.disabled = false; }
}

async function callApi(){
  hideAll();
  setLoading(true);
  out.textContent = "Calling…";
  try {
    const res = await fetch("/api/ping", { method: "GET", credentials: "same-origin" });
    const txt = await res.text();

    if (res.status === 429) {
      show(rate429Box);
      out.textContent = txt || "Rate limited by WAF (429).";
      return;
    }
    if (res.status === 403) {
      show(waf403Box);
      out.textContent = txt || "Blocked by WAF (403). JWT missing/invalid.";
      return;
    }
    if (res.status === 401) {
      show(expiredBox);
      out.textContent = txt || "Unauthorized (401).";
      return;
    }

    // success & others
    try { out.textContent = JSON.stringify(JSON.parse(txt), null, 2); }
    catch { out.textContent = txt; }
    // show success badge only for 2xx
    if (res.ok) show(okBox);
  } catch (e) {
    genericErr.textContent = "⚠️ Network error. If a WAF sits in front, ensure a valid JWT cookie and try again.";
    show(genericErr);
    out.textContent = String(e);
  } finally {
    setLoading(false);
  }
}
btn.onclick = callApi;

function tick(){
  if(!exp){ cd.textContent = "--"; return; }
  const now = Math.floor(Date.now()/1000);
  const remain = Math.max(0, exp - now);
  cd.textContent = remain;
}
tick(); setInterval(tick, 1000);
</script>
</body>
</html>
"""

def issue_jwt_for_uid(uid: str):
    now = datetime.now(timezone.utc)
    iat = int(now.timestamp())
    nbf = iat - LEEWAY_SECONDS
    exp = iat + 30
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": uid,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "jti": uuid.uuid4().hex,
    }
    headers = {"alg": ALG, "kid": KID, "typ": "JWT"}
    token = jwt.encode(claims, private_pem(), algorithm=ALG, headers=headers)
    return token, exp

def set_session(resp, token: str, exp: int):
    # HttpOnly + Secure + SameSite=Lax to prevent frontend access and CSRF/Referer leakage
    # Secure requires HTTPS; adjust if local testing
    resp.set_cookie(
        COOKIE_NAME, token,
        max_age=32, httponly=True, secure=False, samesite="Lax", path="/"
    )
    # Non-sensitive exp for frontend countdown (optional)
    resp.set_cookie(
        COOKIE_EXP, str(exp),
        max_age=32, httponly=False, secure=False, samesite="Lax", path="/demo"
    )

def clear_session(resp):
    resp.delete_cookie(COOKIE_NAME, path="/")
    resp.delete_cookie(COOKIE_EXP, path="/demo")

@app.get("/")
def index():
    return render_template_string(INDEX_HTML, alg=ALG, kid=KID, iss=ISSUER, aud=AUDIENCE)

@app.post("/issue")
def issue():
    uid = (request.form.get("uid") or "").strip()
    if not uid:
        return "UID is required", 400
    token, exp = issue_jwt_for_uid(uid)
    resp = make_response(redirect(url_for("demo")))
    set_session(resp, token, exp)
    return resp

@app.get("/demo")
def demo():
    exp_cookie = request.cookies.get(COOKIE_EXP)
    try:
        exp_int = int(exp_cookie) if exp_cookie else 0
    except ValueError:
        exp_int = 0
    return render_template_string(DEMO_HTML, alg=ALG, kid=KID, iss=ISSUER, aud=AUDIENCE, exp=exp_int)

@app.get("/api/ping")
def api_ping():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return jsonify({"ok": False, "error": "Missing JWT (Cookie)"}), 401
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Cannot read header: {e}"}), 400
    try:
        claims = jwt.decode(
            token,
            public_pem(),
            algorithms=[ALG],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]},
            leeway=LEEWAY_SECONDS,
        )
        return jsonify({
            "ok": True,
            "message": "Validation successful",
            "now": int(time.time()),
            "header": header,
            "claims": claims
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"ok": False, "error": "Token expired"}), 401
    except jwt.InvalidAudienceError:
        return jsonify({"ok": False, "error": "aud mismatch"}), 401
    except jwt.InvalidIssuerError:
        return jsonify({"ok": False, "error": "iss mismatch"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"ok": False, "error": f"Invalid Token: {e}"}), 401

@app.get("/reset")
def reset():
    resp = make_response(redirect(url_for("index")))
    clear_session(resp)
    return resp

@app.get("/.well-known/jwks.json")
def jwks():
    resp = jsonify({"keys": [public_jwk_obj()]})
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
