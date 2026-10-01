"""crypto_solve — an executable exploit PRIMITIVE for common CTF crypto (same shape as jwt_forge).

One tool call routes on the args to the right attack instead of the LLM hand-driving openssl/
python one-liners (it always fumbles long_to_bytes and modular inverses). Three families:

  1. RSA (n,e,c or pubkey_path+c) — tried cheapest-first:
       (a) small-e cube root (integer e-th root) when m^e < n
       (b) common-factor GCD when a second modulus n2 is given (shared prime)
       (c) factordb lookup for known factorizations (RsaCtfTool)
       (d) Wiener's attack for small private exponent d
       (e) fall back to shelling out to RsaCtfTool for everything else
  2. Hash cracking (hash [+hash_type]) — identify by length, crack against a builtin list + rockyou.
  3. Classical (ciphertext) — auto-decode chain: base64/base32/hex, ROT-N, single-byte XOR.

Paths (a),(b),(d), the hash loop, and the classical chain are pure stdlib (int math + hashlib), so
they run anywhere python3 does. factordb + the RsaCtfTool fallback shell out to /opt/RsaCtfTool in
the ctf-agent image. Heavy general factorization / lattice attacks (Coppersmith, LLL) are out of
scope — this is the cheap-win layer, not a CAS.
"""
import base64
import json


def _script(params: dict) -> str:
    """The primitive as a self-contained script run inside the sandbox (stdlib-first)."""
    return "import json,sys,os,re,hashlib,base64,binascii,subprocess\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
FLAG=re.compile(rb"[A-Za-z0-9_]{3,20}\{[^}]{3,120}\}")     # flag{..}/picoCTF{..}/HTB{..} shaped
                                                           # ponytail: 3+ char prefix+body cuts XOR garbage like z{z}; widen if a target uses short tags

def l2b(m):                                                # long_to_bytes, stdlib
    if m<=0: return b""
    return m.to_bytes((m.bit_length()+7)//8, "big")

def show_m(m, tag):
    b=l2b(m)
    f=FLAG.search(b)
    print("%s recovered m=%d"%(tag,m))
    print("  bytes: %r"%b)
    if f: print("  FLAG: %s"%f.group().decode("latin-1"))
    return b

def iroot(x, n):                                           # exact integer n-th root or None
    if x<0: return None
    if x==0: return 0
    hi=1
    while hi**n<=x: hi<<=1
    lo=hi>>1
    while lo<hi:
        mid=(lo+hi+1)>>1
        if mid**n<=x: lo=mid
        else: hi=mid-1
    return lo if lo**n==x else None

def rsa_decrypt(c, e, p, q):
    d=pow(e, -1, (p-1)*(q-1))
    return pow(c, d, p*q)

def wiener(e, n):                                          # small-d attack via continued fractions
    a,b=e,n; cf=[]                                         # ponytail: standard textbook Wiener, no fancy bounds
    while b:
        cf.append(a//b); a,b=b,a-(a//b)*b
    num0,num1,den0,den1=0,1,1,0
    for q in cf:
        num=q*num1+num0; den=q*den1+den0                  # convergent k/d = num/den
        num0,num1,den0,den1=num1,num,den1,den
        k,d=num,den
        if k==0: continue
        if (e*d-1)%k: continue
        phi=(e*d-1)//k
        s=n-phi+1                                          # p+q ; solve x^2 - s x + n = 0
        disc=s*s-4*n
        if disc<0: continue
        r=iroot(disc,2)
        if r is None: continue
        if (s+r)%2==0:
            return d
    return None

def load_pubkey(path):                                     # (n,e) from a PEM/DER key — sandbox-side
    try:
        from Crypto.PublicKey import RSA                    # pycryptodome, in the ctf-agent image
        k=RSA.import_key(open(path,"rb").read()); return k.n, k.e
    except Exception as ex:
        print("[rsa-pubkey] pycryptodome load failed (%s); need n/e as decimal strings"%ex); return None,None

def do_rsa():
    c=int(P["c"]); n2=P.get("n2")
    if P.get("n") and P.get("e"):
        n,e=int(P["n"]), int(P["e"])
    else:
        n,e=load_pubkey(P["pubkey_path"])
        if n is None: print("CRYPTO_SOLVE_FAIL rsa: could not read pubkey_path"); return
    # (a) small-e cube root — m^e < n means c is the un-reduced power
    if e<=257:
        r=iroot(c, e)
        if r is not None:
            print("CRYPTO_SOLVE_OK rsa/small-e (e=%d)"%e); show_m(r,"[rsa-cuberoot]"); return
    # (b) common-factor GCD against a second modulus
    if n2:
        from math import gcd
        g=gcd(n, int(n2))
        if 1<g<n:
            print("CRYPTO_SOLVE_OK rsa/common-factor"); show_m(rsa_decrypt(c,e,g,n//g),"[rsa-gcd]"); return
        print("[rsa-gcd] no shared prime between n and n2")
    # (d) Wiener — pure stdlib, cheap; run before shelling out so the test path stays tool-free
    d=wiener(e,n)
    if d is not None:
        print("CRYPTO_SOLVE_OK rsa/wiener (small d)"); show_m(pow(c,d,n),"[rsa-wiener]"); return
    # (c)/(e) factordb + RsaCtfTool — shell out (tools live in the ctf-agent image)
    tool="/opt/RsaCtfTool/RsaCtfTool.py"
    if os.path.exists(tool):
        try:
            r=subprocess.run(["python3",tool,"-n",str(n),"-e",str(e),"--uncipher",str(c),
                              "--attack","factordb,wiener,small_q,fermat,pollard_p_1"],
                             capture_output=True,text=True,timeout=200)
            blob=r.stdout+r.stderr
            if re.search(r"unciphered|flag\{|Results?\s*for", blob, re.I):   # only OK on a real result
                print("CRYPTO_SOLVE_OK rsa/RsaCtfTool (shell-out)"); print(blob[-1500:]); return
            print("[rsa-rsactftool] no result:\n%s"%blob[-600:])
        except Exception as ex:
            print("[rsa-rsactftool] error: %s"%ex)
    print("CRYPTO_SOLVE_FAIL rsa: cube-root/GCD/Wiener/RsaCtfTool exhausted — likely needs a "
          "heavier factorization or lattice attack (out of scope).")

def do_hash():
    h=P["hash"].strip().lower(); ht=(P.get("hash_type") or "").lower()
    algs={32:"md5",40:"sha1",64:"sha256"}
    if not ht: ht=algs.get(len(h))
    if ht not in ("md5","sha1","sha256"):
        print("CRYPTO_SOLVE_FAIL hash: unknown type for length %d (pass hash_type md5/sha1/sha256)"%len(h)); return
    fn=getattr(hashlib, ht)
    cands=["password","123456","admin","letmein","secret","root","toor","qwerty",
           "sunshine","password1","welcome","monkey","dragon","flag"]
    wl=P.get("wordlist") or "/usr/share/wordlists/rockyou.txt"
    def check(w):
        return fn(w.encode()).hexdigest()==h
    for w in cands:
        if check(w):
            print("CRYPTO_SOLVE_OK hash/%s builtin"%ht); print("  PLAINTEXT: %s"%w); return
    if os.path.exists(wl):
        # ponytail: linear scan of the wordlist in-process; fine for rockyou-sized files, shell to
        #           hashcat if you ever need rules/masks or GPU.
        try:
            with open(wl,"rb") as f:
                for line in f:
                    w=line.rstrip(b"\r\n").decode("utf-8","replace")
                    if w and fn(w.encode()).hexdigest()==h:
                        print("CRYPTO_SOLVE_OK hash/%s wordlist=%s"%(ht,wl)); print("  PLAINTEXT: %s"%w); return
        except Exception as ex:
            print("[hash] wordlist read error: %s"%ex)
    print("CRYPTO_SOLVE_FAIL hash: not in builtin list or %s"%wl)

def do_classical():
    raw=P["ciphertext"].strip()
    hits=[]
    def note(label, data):
        if not data: return
        m=FLAG.search(data)
        if m: hits.append((label, m.group().decode("latin-1"), data))
    # candidate decodings to also brute over
    cands=[("raw", raw.encode())]
    for name,fn in (("base64", lambda s: base64.b64decode(s+"="*(-len(s)%4))),
                    ("base32", lambda s: base64.b32decode(s+"="*(-len(s)%8))),
                    ("hex",    lambda s: binascii.unhexlify(re.sub(r"\s","",s)))):
        try: cands.append((name, fn(raw)))
        except Exception: pass
    for label,data in cands:
        note(label, data)                                  # direct decode
        for k in range(256):                               # single-byte XOR
            note("%s^0x%02x"%(label,k), bytes(b^k for b in data))
        for n in range(1,26):                              # ROT-N over ascii letters
            rot=bytes(((b-65+n)%26)+65 if 65<=b<=90 else ((b-97+n)%26)+97 if 97<=b<=122 else b for b in data)
            note("%s/rot%d"%(label,n), rot)
    if hits:
        print("CRYPTO_SOLVE_OK classical (%d flag hit(s))"%len(hits))
        seen=set()
        for label,flag,data in hits:
            if flag in seen: continue
            seen.add(flag); print("  [%s] %s"%(label,flag))
        return
    # no flag shape — surface the most-printable decode so a human can eyeball it
    best=None
    for label,data in cands:
        if not data: continue
        pr=sum(32<=b<127 for b in data)/len(data)
        if best is None or pr>best[0]: best=(pr,label,data)
    if best and best[0]>0.9:
        print("CRYPTO_SOLVE_OK classical: no flag shape, most-printable decode:")
        print("  [%s] %r"%(best[1], best[2][:200]))
    else:
        print("CRYPTO_SOLVE_FAIL classical: no flag and nothing decoded to printable text.")

if P.get("hash"):
    do_hash()
elif P.get("c") is not None and (P.get("n") and P.get("e") or P.get("pubkey_path")):
    do_rsa()
elif P.get("ciphertext"):
    do_classical()
else:
    print("CRYPTO_SOLVE_FAIL usage: give RSA {n,e,c[,n2]} or {pubkey_path,c}, or {hash[,hash_type]}, "
          "or {ciphertext}.")
'''


def run(sb, args: dict) -> str:
    """Validate args, run the primitive script in the sandbox, return its output."""
    params = {}
    # RSA: accept a pubkey file (parsed in-sandbox by RsaCtfTool/pycryptodome) or raw n,e.
    pub = (args.get("pubkey_path") or "").strip()
    have_rsa_ints = args.get("n") and args.get("e") and args.get("c") is not None
    if args.get("hash"):
        params["hash"] = str(args["hash"])
        if args.get("hash_type"):
            params["hash_type"] = str(args["hash_type"])
        if args.get("wordlist"):
            params["wordlist"] = str(args["wordlist"])
    elif have_rsa_ints or (pub and args.get("c") is not None):
        if args.get("c") is None:
            return "crypto_solve error: RSA needs the ciphertext c (decimal string)."
        for k in ("n", "e", "c", "n2"):
            if args.get(k) is not None:
                try:
                    int(str(args[k]))                       # decimal-string big ints
                except ValueError:
                    return f"crypto_solve error: RSA param {k!r} must be a decimal integer string."
                params[k] = str(args[k])
        if pub and not have_rsa_ints:
            params["pubkey_path"] = pub                     # n,e extracted sandbox-side via pycryptodome
    elif args.get("ciphertext"):
        params["ciphertext"] = str(args["ciphertext"])
    else:
        return ("crypto_solve error: nothing to route on — give RSA {n,e,c[,n2]}, a {hash}, "
                "or a {ciphertext}.")
    b64 = base64.b64encode(_script(params).encode()).decode()
    return sb.bash(f"echo {b64} | base64 -d | python3 -", timeout=300)
