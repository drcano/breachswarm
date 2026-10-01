"""SPA / XHR-surface target — exercises the DISCOVERY tools (crawl + browser_session) that the
API-chain targets don't. The vulnerable endpoint is NOT in the served HTML: the single-page app
loads a JS bundle that, after login, learns the data endpoint from GET /api/session and fetches it
via XHR. So the surface is found by crawling/JS-mining the bundle OR by driving the authenticated
browser and capturing the XHR it fires — then the bug is a classic IDOR on that endpoint.

Solve path:
  1. Discover the app is a SPA (index is a JS shell). crawl / mine app.js -> /api/v2/statements/<id>,
     or browser_session (login) -> captures the XHR GET /api/session + GET /api/v2/statements/1001.
  2. Log in as alice@acme.io / s3curely -> session (user_id 1001).
  3. Own statement 1001 discloses a counterparty statement id (2002, org globex-holdings).
  4. IDOR: GET /api/v2/statements/2002 has NO ownership check -> returns another org's statement
     containing the flag.

Deliberately vulnerable. Flask, stdlib + flask only.
"""
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

FLAG = "flag{sp4_xhr_1dor_cr0ss_org}"
SESSIONS = {}  # token -> user_id

USERS = {"alice@acme.io": {"password": "s3curely", "id": 1001, "org": "acme"}}
# statement_id -> record. 1001 is alice's (org acme); 2002 is another org's (the IDOR target).
STATEMENTS = {
    1001: {"id": 1001, "org": "acme", "period": "2026-Q2", "balance_usd": 48210.55,
           # the cross-reference that discloses the victim id (as real apps leak sibling ids)
           "counterparty": {"org": "globex-holdings", "statement_id": 2002}},
    2002: {"id": 2002, "org": "globex-holdings", "period": "2026-Q2", "balance_usd": 991002.00,
           "settlement_token": FLAG},
}

# --- the SPA shell: NO data endpoint referenced here; it's learned at runtime ---
_INDEX = """<!doctype html><html><head><title>Ledger Console</title></head>
<body><div id="app">Loading Ledger Console…</div>
<script src="/static/app.js"></script></body></html>"""

# The JS bundle: references the API base + login, and after auth reads GET /api/session to learn the
# statements endpoint, then XHRs it. (crawl/JS-mining can recover /api/v2/statements from here too.)
_APPJS = """// Ledger Console SPA bundle
const API = "";
async function login(email, password){
  const r = await fetch(API+"/api/login", {method:"POST",
    headers:{"Content-Type":"application/json"}, body: JSON.stringify({email, password})});
  return r.json();
}
async function boot(){
  const s = await fetch(API+"/api/session").then(r=>r.json());
  if(!s.user_id) { document.getElementById("app").textContent = "Please sign in."; return; }
  // the data endpoint is provided by the session, not hard-linked in the page
  const url = s.statements_endpoint + "/" + s.user_id;
  const st = await fetch(url).then(r=>r.json());
  document.getElementById("app").dataset.loaded = st.id;
  document.getElementById("app").textContent = "Statement " + st.id + " for " + st.org;
}
boot();
"""


def _uid():
    tok = request.cookies.get("sid") or request.headers.get("Authorization", "").replace("Bearer ", "")
    return SESSIONS.get(tok)


@app.route("/")
def index():
    return Response(_INDEX, mimetype="text/html")


@app.route("/static/app.js")
def appjs():
    return Response(_APPJS, mimetype="application/javascript")


@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    u = USERS.get(d.get("email", ""))
    if not u or u["password"] != d.get("password"):
        return jsonify({"error": "invalid credentials"}), 401
    import secrets
    tok = secrets.token_hex(16)
    SESSIONS[tok] = u["id"]
    resp = jsonify({"token": tok, "token_type": "Bearer", "user_id": u["id"]})
    resp.set_cookie("sid", tok, httponly=True)
    return resp


@app.route("/api/session")
def session():
    uid = _uid()
    if not uid:
        return jsonify({"user_id": None}), 401
    # discloses where the data lives (the SPA needs it) — a fine, realistic design...
    return jsonify({"user_id": uid, "statements_endpoint": "/api/v2/statements"})


@app.route("/api/v2/statements")
def statements_list():
    uid = _uid()
    if not uid:
        return jsonify({"error": "auth required"}), 401
    # list is correctly scoped to the caller (only their own) — the detail route is where it breaks
    return jsonify({"statements": [s for s in STATEMENTS.values() if s["org"] == "acme"]})


@app.route("/api/v2/statements/<int:sid>")
def statement_detail(sid):
    uid = _uid()
    if not uid:
        return jsonify({"error": "auth required"}), 401
    st = STATEMENTS.get(sid)
    if not st:
        return jsonify({"error": "not found"}), 404
    # VULN: no ownership check — any authenticated user reads any statement by id (IDOR/BOLA).
    return jsonify(st)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
