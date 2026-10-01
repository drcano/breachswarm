"""Isolated NoSQLi auth-bypass target (M2). Single endpoint so the benchmark
measures the intended operator-injection path, not an opportunistic flag grab
from a sibling vuln sharing the host."""
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "flag{m2_nosql_operator_injection}"


@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(force=True, silent=True) or {}
    user, pw = body.get("user"), body.get("pass")
    # VULN: operator object ({"$ne": null}) matches any password (Mongo-style)
    if isinstance(pw, dict) and any(k.startswith("$") for k in pw):
        return jsonify(ok=True, flag=FLAG, msg="logged in as admin (operator injection)")
    if user == "admin" and pw == "S3cretAdminPw!":
        return jsonify(ok=True, msg="logged in")
    return jsonify(ok=False, msg="invalid credentials"), 401


@app.route("/")
def index():
    return "Auth API. POST JSON {user, pass} to /api/login."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
