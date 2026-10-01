"""GraphQL BOLA target — a /graphql endpoint with introspection enabled and a user(id:) resolver
that has NO authorization check: any authenticated caller reads any user by id (the GraphQL BOLA
pattern the `graphql` primitive is built to surface). Hand-rolled (no graphene dep): it matches the
introspection query and the user(id:)/me query shapes leniently.

Solve: introspect -> see User.recoveryToken + user(id:) resolver -> query user(id:2) -> flag.
Deliberately vulnerable. Flask.
"""
import re
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "flag{gr4phql_b0l4_n0_4uthz_0n_n0de}"

USERS = {
    1: {"id": 1, "email": "alice@acme.io", "role": "member", "recoveryToken": "tok-alice-benign"},
    2: {"id": 2, "email": "root@globex.io", "role": "admin", "recoveryToken": FLAG},
}
SESSIONS = {"guest-token": 1}   # a low-priv session; the bug is that it can read user(id:2)

_SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "User", "kind": "OBJECT", "fields": [
            {"name": "id"}, {"name": "email"}, {"name": "role"}, {"name": "recoveryToken"}]},
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "me"}, {"name": "user"}, {"name": "node"}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "login"}, {"name": "resetPassword"}, {"name": "deleteUser"}]},
    ]}}}


def _authed():
    tok = request.cookies.get("sid") or request.headers.get("Authorization", "").replace("Bearer ", "")
    return SESSIONS.get(tok) or SESSIONS.get("guest-token")   # lenient: default guest for the demo


@app.route("/")
def index():
    return "GraphQL API at POST /graphql (introspection enabled)."


@app.route("/graphql", methods=["POST", "GET"])
def graphql():
    d = request.get_json(silent=True) or {}
    q = d.get("query") or request.args.get("query") or ""
    if "__schema" in q or "__type" in q:
        return jsonify(_SCHEMA)
    uid = _authed()
    m = re.search(r"user\s*\(\s*id\s*:\s*(\d+)", q)
    if m:
        # VULN: returns the requested user with NO check that it belongs to the caller (BOLA).
        target = USERS.get(int(m.group(1)))
        if not target:
            return jsonify({"data": {"user": None}})
        return jsonify({"data": {"user": target}})
    if re.search(r"\bme\b", q):
        return jsonify({"data": {"me": USERS.get(uid)}})
    return jsonify({"errors": [{"message": "unknown query; try {__schema} or {user(id:N){...}}"}]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
