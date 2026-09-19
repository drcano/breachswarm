"""Bastion — a TWO-STAGE target that forces the full kill chain on one host: a JWT
auth-escalation INTO a WAF'd blind-SQLi extraction. Models a real authenticated API where
the injectable surface lives behind `role=admin`, so a scanner that can't first mint an admin
token never reaches the SQLi at all.

  STAGE 1 — AUTH GATE (JWT). `/api/search` needs `Authorization: Bearer <jwt>` (or a `token`
    cookie) whose payload has `role=admin`; anything else is 401. `/api/session` hands out a
    LOW-PRIV token `{user:"guest", role:"user"}`, HS256-signed with a weak secret. Two real
    verifier bugs let the attacker escalate — BOTH work, so it's robustly solvable:
      (a) alg:none is accepted without any signature check (classic), and
      (b) the HS256 secret is a weak, guessable value, so a crack + re-sign also works.
    JWT crypto is pure stdlib (hmac/hashlib/base64/json) — no pyjwt needed.

  STAGE 2 — WAF'd BLIND SQLi (Citadel's proven core, polymorphic like Citadel-Poly). Once
    role=admin, `/api/search` is the Citadel surface: a WAF on the RAW query string, boolean-
    blind-only responses (present vs empty, no errors/reflection), an escalating rate limiter,
    and per-instance polymorphism seeded at boot (WAF decode depth, injectable param name,
    rate threshold/window). The flag is extracted char-by-char through the blind oracle.

Deliberately vulnerable — authorized lab target only. Intended solve: recon the index -> grab
the low-priv token from /api/session -> escalate via alg:none (or weak-secret crack) -> encode
`select` past the WAF at this instance's depth -> binary-search
`ascii(substr((select flag from secrets),i,1))` under the rate limit.
"""
import os
import re
import time
import json
import hmac
import base64
import random
import hashlib
from collections import defaultdict
from urllib.parse import unquote

from flask import Flask, request, jsonify

from citadel_app import _VALID_IDS  # single-source the valid-id set; FLAG/_cond are bastion's own

app = Flask(__name__)

FLAG = "flag{b4st10n_jwt_w4f_bl1nd_ch41n}"    # extracted char-by-char via blind SQLi (Stage 2)
DECOY = "flag{debug_console_is_a_decoy}"

# --- Stage 1: JWT. Weak HS256 secret picked from a small common list (crackable path). ---
WEAK_SECRETS = ["secret", "changeme", "s3cr3t", "password", "admin"]

# --- per-instance polymorphic config, seeded at boot (BASTION_SEED / CITADEL_SEED to reproduce) ---
_seed = os.getenv("BASTION_SEED") or os.getenv("CITADEL_SEED")
_rng = random.Random(int(_seed) if _seed and _seed.lstrip("-").isdigit() else None)
SECRET = _rng.choice(WEAK_SECRETS)              # the (weak) HS256 signing secret for this instance
WAF_DEPTH = _rng.choice([0, 1, 2])              # times the WAF decodes before keyword matching
PARAM = _rng.choice(["q", "id", "item", "p"])   # injectable parameter name
RATE_MAX = _rng.choice([6, 7, 8, 9, 10])        # requests per window before throttling
RATE_WIN = _rng.choice([2.0, 3.0, 4.0])         # sliding window, seconds
JITTER_MS = _rng.choice([0, 50, 100, 150])      # per-request latency jitter ceiling


# --------------------------- stdlib JWT (base64url, HS256) ---------------------------
def _b64e(b) -> str:                            # base64url encode, strip padding
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:                     # base64url decode, tolerate missing padding
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign_hs256(signing_input: str, secret: str) -> str:
    return _b64e(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())


def _make_hs256(payload: dict, secret: str = None) -> str:
    secret = SECRET if secret is None else secret
    si = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":"))) + "." + \
        _b64e(json.dumps(payload, separators=(",", ":")))
    return si + "." + _sign_hs256(si, secret)


def _verify_jwt(token: str):
    """Return the payload if the token 'verifies', else None. Two DELIBERATE bugs live here:
    alg:none is trusted with no signature, and the HS256 path checks against a weak secret."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
    except Exception:
        return None
    alg = str(header.get("alg", ""))
    if alg.lower() == "none":                   # BUG (a): alg:none accepted, signature ignored
        return payload
    if alg == "HS256":                          # BUG (b): secret is weak/guessable
        if hmac.compare_digest(_sign_hs256(parts[0] + "." + parts[1], SECRET), parts[2]):
            return payload
    return None


def _authed():
    """Extract the bearer/cookie token and return its verified payload, or None."""
    h = request.headers.get("Authorization", "")
    tok = h[7:].strip() if h.startswith("Bearer ") else request.cookies.get("token", "")
    return _verify_jwt(tok) if tok else None


# ------------------- Stage 2: WAF + blind oracle (Citadel's shapes, bastion's FLAG) -------------------
_WAF = re.compile(
    r"\b(union|select|or|and|sleep|benchmark|updatexml|extractvalue|having|group_concat|"
    r"information_schema|load_file|outfile)\b|['\"]|--|#|/\*|\bxp_|0x[0-9a-f]", re.I)


def _decode(s: str, n: int) -> str:
    """Decode exactly n times (what the WAF sees)."""
    for _ in range(n):
        s2 = unquote(s)
        if s2 == s:
            break
        s = s2
    return s


def _decode_fixpoint(s: str) -> str:
    """Decode until stable (what the app sees) — so ANY encode depth >= WAF_DEPTH+1 reaches the DB."""
    for _ in range(6):
        s2 = unquote(s)
        if s2 == s:
            return s
        s = s2
    return s


# Copied from citadel_app._cond so the shapes match EXACTLY, but bound to bastion's own FLAG
# (citadel's oracle extracts citadel's flag; this one must extract bastion's). Intended shapes
# only, no error leak — purely blind.
def _cond(expr: str) -> bool:
    e = expr.lower().replace(" ", "")
    if "flagfromsecrets" not in e.replace("select", "").replace("(", "").replace(")", ""):
        if "selectflagfromsecrets" not in e:
            return False
    m = re.search(r"ascii\(substr\(\(selectflagfromsecrets\),(\d+),1\)\)(>|<|=)(\d+)", e)
    if m:
        pos, op, val = int(m.group(1)), m.group(2), int(m.group(3))
        if not (1 <= pos <= len(FLAG)):
            return False
        c = ord(FLAG[pos - 1])
        return c > val if op == ">" else c < val if op == "<" else c == val
    m = re.search(r"length\(\(selectflagfromsecrets\)\)(>|<|=)(\d+)", e)
    if m:
        op, val = m.group(1), int(m.group(2))
        n = len(FLAG)
        return n > val if op == ">" else n < val if op == "<" else n == val
    m = re.search(r"substr\(\(selectflagfromsecrets\),(\d+),1\)=chr\((\d+)\)", e)
    if m:
        pos, val = int(m.group(1)), int(m.group(2))
        return 1 <= pos <= len(FLAG) and ord(FLAG[pos - 1]) == val
    return False


# --- rate limiter: >RATE_MAX req / RATE_WIN -> 429 + escalating ban per client ---
_hits = defaultdict(list)
_ban_until = defaultdict(float)
_ban_level = defaultdict(int)


def _rate_limited() -> bool:
    now = time.time()
    key = request.remote_addr or "x"
    if now < _ban_until[key]:
        return True
    _hits[key] = [t for t in _hits[key] if now - t < RATE_WIN]
    _hits[key].append(now)
    if len(_hits[key]) > RATE_MAX:
        _ban_level[key] = min(_ban_level[key] + 1, 6)
        _ban_until[key] = now + 2 ** _ban_level[key]
        return True
    return False


@app.route("/")
def index():
    # hint the two-stage flow + the injectable param, but not the WAF depth, rate, or secret
    return (f"Bastion API (edge build v{WAF_DEPTH}{RATE_MAX}). "
            f"GET /api/session issues a session token; send it as 'Authorization: Bearer <jwt>'. "
            f"GET /api/search?{PARAM}=<id> returns matching products but requires role=admin. "
            "Behind a WAF; abusive clients are throttled.")


@app.route("/api/session")
def session():
    tok = _make_hs256({"user": "guest", "role": "user"})
    return jsonify(token=tok, token_type="Bearer",
                   note="low-priv session token (role=user); /api/search needs role=admin")


@app.route("/api/search")
def search():
    if JITTER_MS:
        time.sleep(_rng.uniform(0, JITTER_MS) / 1000.0)
    payload = _authed()                                         # Stage 1: auth gate
    if not payload or payload.get("role") != "admin":
        return jsonify(error="401 unauthorized — valid admin token required"), 401
    raw = request.query_string.decode("latin-1", "replace")    # RAW bytes (pre-decode)
    if _rate_limited():
        return jsonify(error="429 rate limit — slow down"), 429
    if _WAF.search(_decode(raw, WAF_DEPTH)):                    # WAF normalizes d times, then matches
        return jsonify(error="request rejected"), 403
    q = _decode_fixpoint(request.args.get(PARAM, ""))          # app decodes to a fixed point
    m = re.match(r"^\s*(\d+)\s*(\|\||&&)\s*(.+)$", q, re.S)
    if m:
        base = int(m.group(1)) in _VALID_IDS
        cond = _cond(m.group(3))
        present = (base or cond) if m.group(2) == "||" else (base and cond)
    else:
        present = q.strip().isdigit() and int(q) in _VALID_IDS
    return jsonify(products=([{"id": 1, "name": "Widget"}] if present else []))


@app.route("/api/debug")
def debug():
    return jsonify(status="ok", flag=DECOY, note="debug console")


@app.route("/api/status")
def status():
    time.sleep(1.2)                                            # tarpit
    return jsonify(status="degraded, retry"), 503


print(f"[bastion] SECRET={SECRET!r} WAF_DEPTH={WAF_DEPTH} PARAM={PARAM} "
      f"RATE={RATE_MAX}/{RATE_WIN}s JITTER<={JITTER_MS}ms", flush=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
