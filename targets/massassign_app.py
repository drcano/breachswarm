"""Mass-assignment target — the profile-update endpoint binds the WHOLE request body onto the user
record, including a `role` field the UI never sends. Set role=admin on your own profile, then the
admin-only endpoint accepts you.

Solve: login -> PATCH /api/me {"role":"admin"} (mass_assign) -> GET /api/admin/flag.
Deliberately vulnerable. Flask.
"""
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "flag{m4ss_4ss1gn_r0le_3sc4l4t10n}"

SESSIONS = {}   # token -> email
USERS = {"alice@acme.io": {"password": "wanderlust", "role": "member", "name": "Alice",
                           "email": "alice@acme.io"}}


def _user():
    tok = request.cookies.get("sid") or request.headers.get("Authorization", "").replace("Bearer ", "")
    email = SESSIONS.get(tok)
    return USERS.get(email) if email else None


@app.route("/")
def index():
    return "Account API. POST /api/login, GET/PATCH /api/me, GET /api/admin/flag (admins only)."


@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    u = USERS.get(d.get("email", ""))
    if not u or u["password"] != d.get("password"):
        return jsonify({"error": "invalid credentials"}), 401
    import secrets
    tok = secrets.token_hex(16)
    SESSIONS[tok] = d["email"]
    resp = jsonify({"token": tok, "token_type": "Bearer", "role": u["role"]})
    resp.set_cookie("sid", tok, httponly=True)
    return resp


@app.route("/api/me", methods=["GET", "PATCH"])
def me():
    u = _user()
    if not u:
        return jsonify({"error": "auth required"}), 401
    if request.method == "GET":
        return jsonify({k: v for k, v in u.items() if k != "password"})
    d = request.get_json(silent=True) or {}
    # VULN: mass assignment — every field in the body is bound onto the record, including 'role'.
    for k, v in d.items():
        if k != "password":
            u[k] = v
    return jsonify({k: v for k, v in u.items() if k != "password"})


@app.route("/api/admin/flag")
def admin_flag():
    u = _user()
    if not u:
        return jsonify({"error": "auth required"}), 401
    if u.get("role") != "admin":
        return jsonify({"error": "forbidden — admin role required", "your_role": u.get("role")}), 403
    return jsonify({"flag": FLAG})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
