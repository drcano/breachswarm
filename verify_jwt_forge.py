"""Live self-check for the jwt_forge exploit primitive (primitives.jwt_forge.run).

Builds an HS256 token signed with 'secret123', runs the primitive, and asserts it
(a) cracks the weak secret from its builtin list and forges a role=admin token whose
signature VERIFIES under 'secret123' (we recompute the HMAC here), and (b) emits an
alg:none variant whose payload decodes to include the overridden claims.

Pure crypto — no server/port needed. Run: ./.venv/bin/python verify_jwt_forge.py
"""
import base64
import hashlib
import hmac
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from primitives import jwt_forge


class HostSB:
    """Minimal sandbox shim: run the primitive's script on the host (python3 + base64)."""
    def bash(self, cmd: str) -> str:
        return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                              timeout=120).stdout


def b64e(b):
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s.encode() + b"=" * (-len(s) % 4))


def make_hs256(payload, secret):
    hdr = b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")))
    pl = b64e(json.dumps(payload, separators=(",", ":")))
    si = hdr + "." + pl
    sig = b64e(hmac.new(secret.encode(), si.encode(), hashlib.sha256).digest())
    return si + "." + sig


def tokens_by_label(out):
    """Pull '[label] token' lines into {label: token}."""
    d = {}
    for line in out.splitlines():
        m = re.match(r"\[([^\]]+)\]\s+(\S+)", line)
        if m:
            d[m.group(1)] = m.group(2)
    return d


if __name__ == "__main__":
    token = make_hs256({"sub": "1000", "role": "user"}, "secret123")

    out = jwt_forge.run(HostSB(), {"token": token, "claims": {"role": "admin", "sub": "1"}})
    print(out.strip())
    assert "JWT_FORGE_OK" in out, "primitive did not run"
    labels = tokens_by_label(out)

    # (a) cracked the weak secret and forged a token that verifies under 'secret123'
    assert "SECRET FOUND: 'secret123' (builtin)" in out, "did not crack builtin weak secret"
    forged = labels.get("hmac-forge/HS256")
    assert forged, "no HS256 forged token emitted"
    h, p, s = forged.split(".")
    assert hmac.compare_digest(
        s, b64e(hmac.new(b"secret123", (h + "." + p).encode(), hashlib.sha256).digest())
    ), "forged HS256 signature does not verify under secret123"
    claims = json.loads(b64d(p))
    assert claims["role"] == "admin" and claims["sub"] == "1", f"claims not overridden: {claims}"
    print("  ok  cracked secret123, forged role=admin token that verifies")

    # (b) alg:none variant decodes to the overridden claims, empty signature
    none_tok = labels.get("alg-none/none")
    assert none_tok and none_tok.endswith("."), "alg:none token should have an empty signature"
    nh, np_, _ = none_tok.split(".")
    assert json.loads(b64d(nh))["alg"] == "none"
    nclaims = json.loads(b64d(np_))
    assert nclaims["role"] == "admin" and nclaims["sub"] == "1", f"alg:none claims wrong: {nclaims}"
    print("  ok  alg:none variant carries the overridden claims")

    # arg guards
    assert "'token' is required" in jwt_forge.run(HostSB(), {})
    assert "not a JWT" in jwt_forge.run(HostSB(), {"token": "garbage"})
    print("  ok  arg validation")
    print("\njwt_forge verified: one call, cracks weak HMAC + emits alg:none, claims overridden")
