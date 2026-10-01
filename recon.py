"""Recon pass — runs BEFORE the specialist, in the same sandbox.

Cheap, deterministic shell probes (no LLM) that (1) sharpen routing when the
challenge has no category label and (2) hand the specialist a ready-made brief
so it starts informed instead of rediscovering the filesystem.

D-CIPHER calls this role the "auto-prompter"; here it's mostly `file`+`strings`.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


_SECRET_FETCH = r'''D=$(mktemp -d); cd "$D"; curl -s -m 8 "__U__/" -o index.html 2>/dev/null
for j in $(grep -oiE 'src="[^"]+\.js"' index.html | sed -E 's/src="([^"]+)".*/\1/' | head -__N__); do
  case "$j" in http*) J="$j";; /*) J="__U__$j";; *) J="__U__/$j";; esac
  f=$(echo "$J" | tr -c 'A-Za-z0-9._-' '_'); curl -s -m 8 "$J" -o "$f.js" 2>/dev/null
done
trufflehog filesystem "$D" --only-verified --json --no-update 2>/dev/null; rm -rf "$D"'''


def _parse_nuclei(jsonl: str) -> list[dict]:
    """Parse nuclei -jsonl output into compact, severity-ranked findings."""
    out = []
    for line in (jsonl or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        info = o.get("info", {}) or {}
        out.append({"severity": (info.get("severity") or "info").lower(),
                    "name": info.get("name") or o.get("template-id", ""),
                    "matched": o.get("matched-at") or o.get("host", ""),
                    "template": o.get("template-id", "")})
    return sorted(out, key=lambda f: _SEV_ORDER.get(f["severity"], 9))


_JS_INTERESTING = re.compile(
    r"api|v\d|rest|graphql|internal|admin|user|account|auth|oauth|token|key|secret|upload|"
    r"export|download|webhook|callback|invite|reset|impersonate|debug|config|feature", re.I)


def _mine_js(text: str) -> list[str]:
    """Extract hidden API endpoints / routes from JS-bundle (or source-map) text. Top hunters'
    highest-yield edge: the niche, in-scope surface lives in the JS, not the visible UI."""
    eps: set[str] = set()
    for m in re.findall(r"""["'`](/[a-zA-Z0-9_][a-zA-Z0-9_/\-.:{}]{1,70})(?:\?[^"'`]*)?["'`]""",
                        text or ""):
        if _JS_INTERESTING.search(m):
            eps.add(m.split("?")[0])
    for m in re.findall(r"""(?:fetch|axios\.\w+|url\s*[:=]|baseURL\s*[:=])\s*[("'`]([^"'`)]+)""",
                        text or ""):
        if (m.startswith("/") or m.startswith("http")) and _JS_INTERESTING.search(m):
            eps.add(m.split("?")[0][:80])
    return sorted(eps)[:60]


def mine_js_endpoints(sb, url: str, max_bundles: int = 6) -> str:
    """Fetch the page's JS bundles (+ .map source maps) and mine them for hidden API endpoints/
    routes — recon WIDE before deep. No-op-ish when there are no bundles."""
    u = url.rstrip("/")
    cmd = rf"""
U="{u}"
H=$(curl -s -m 8 "$U/")
echo "$H" | grep -oiE 'src="[^"]+\.js[^"]*"' | sed -E 's/.*src="([^"]+)".*/\1/' | head -{max_bundles} | while read js; do
  case "$js" in http*) J="$js";; /*) J="$U$js";; *) J="$U/$js";; esac
  curl -s -m 8 "$J"; echo; curl -s -m 8 "$J.map" 2>/dev/null; echo
done
"""
    eps = _mine_js(sb.bash(cmd, timeout=120))
    if not eps:
        return ""
    return "== hidden endpoints mined from JS bundles / source maps (recon wide) ==\n" + \
           "\n".join(f"  {e}" for e in eps)


# Endpoints whose NAME screams "bug lives here" — legacy/admin/debug/internal/undocumented surface
# a company forgot about. Distinct from _JS_INTERESTING (which just decides "is this an endpoint").
_WEIRD = re.compile(
    r"admin|debug|internal|\btest\b|legacy|deprecat|backup|\.bak|/config|export|import|actuator|"
    r"swagger|openapi|graphql|\.git|\.env|webhook|callback|\bsso\b|oauth|saml|impersonat|masquerad|"
    r"sudo|\broot\b|/dev|staging|\bbeta\b|\bv0\b|private|/raw|proxy|fetch|redirect|upload|download|"
    r"/exec|/cmd|/run|eval|render|template|preview|api[_-]?key|token|secret|password|reset|invite|"
    r"metrics|/health|/status|/trace|feature.?flag|/su\b|_internal|/api/internal", re.I)
_BORING = re.compile(r"\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|map|webp|mp4|json)(\?|$)", re.I)


def _crt_subdomains(data: list, domain: str) -> list[str]:
    """Parse crt.sh JSON rows into unique subdomains of `domain` (pure — unit-testable)."""
    subs = set()
    for row in data or []:
        for nv in (row.get("name_value", "") or "").split("\n"):
            nv = nv.strip().lower().lstrip("*.")
            if nv.endswith("." + domain) and "@" not in nv and "*" not in nv:
                subs.add(nv)
    return sorted(subs)


def enum_subdomains(domain: str, timeout: float = 40) -> list[str]:
    """Passive subdomain enumeration via Certificate Transparency logs (crt.sh). No traffic to the
    target — just public CT-log data. The highest-yield recon step: the forgotten hosts a company
    stopped maintaining (staging/uat/legacy/admin) are where bugs survive."""
    import urllib.request, urllib.parse
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    for _ in range(3):
        try:
            raw = urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=timeout).read()
            if raw[:1] == b"[":
                return _crt_subdomains(json.loads(raw), domain)
        except Exception:
            pass
        time.sleep(3)
    return []


def _is_exposed(status: str, server: str) -> bool:
    """An origin answering directly (Server header not a CDN/WAF, live status) is a WAF-bypass /
    forgotten-surface signal — the single highest-value thing subdomain recon finds."""
    s = (server or "").lower()
    cdn = ("cloudflare", "akamai", "fastly", "cloudfront", "sucuri", "imperva", "incapsula")
    return bool(server and not any(c in s for c in cdn) and status not in ("000", "ERR", "404"))


def sweep_hosts(hosts, header: str = "", timeout: int = 5) -> list[dict]:
    """Probe each host's root: status + Server. Flags exposed origins (see _is_exposed)."""
    import concurrent.futures
    hdr = ["-H", header] if header else []
    def probe(h):
        try:
            out = subprocess.run(["curl", "-s", "-m", str(timeout), *hdr, "-o", "/dev/null",
                                  "-w", "%{http_code}", "-D", "-", "https://" + h + "/"],
                                 capture_output=True, text=True, timeout=timeout + 3).stdout
            code = out.strip().split("\n")[-1].strip()
            server = next((l.split(":", 1)[1].strip() for l in out.split("\n")
                           if l.lower().startswith("server:")), "")
            return {"host": h, "status": code, "server": server, "exposed": _is_exposed(code, server)}
        except Exception:
            return {"host": h, "status": "ERR", "server": "", "exposed": False}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        return list(ex.map(probe, list(hosts)))


def flag_interesting(paths, status: dict | None = None) -> list[tuple]:
    """Rank endpoints by how WORTH-PRESSING they look (name signals + status anomalies). Returns
    [(path, score, [reasons]), ...] most-interesting first — the weird/forgotten ones to hammer."""
    status = status or {}
    scored = []
    for p in dict.fromkeys(x for x in paths if x):     # dedup, preserve order
        if _BORING.search(p):
            continue
        reasons = []
        m = _WEIRD.search(p)
        if m:
            reasons.append("name:" + m.group(0).strip("/"))
        st = status.get(p)
        if st == 500:
            reasons.append("500-error-surface")
        elif st in (401, 403):
            reasons.append(f"auth-gated({st})")
        elif st == 405:
            reasons.append("method-sensitive(405)")
        if "/_" in p or p.strip("/").startswith("_"):
            reasons.append("underscore-internal")
        if reasons:
            score = len(reasons) + (2 if any(r.startswith("name:") for r in reasons) else 0)
            scored.append((p, score, reasons))
    scored.sort(key=lambda x: -x[1])
    return scored


def nuclei_sweep(sb, url: str, rate: int = 5, timeout: int = 240) -> str:
    """Run nuclei (if installed) against an AUTHORIZED target, rate-limited, and return a compact
    severity-ranked summary of known CVEs / exposures / misconfigs — the one external tool that's
    a real force-multiplier on real targets. No-op if nuclei isn't installed. Idea pulled from
    agentic-bug-hunter's installed-gated tool pipeline; here it's opt-in (CTF_NUCLEI=1) so it never
    adds scan noise to the deterministic lab bench, and `rate` should be set from the engagement RoE."""
    if "yes" not in sb.bash("command -v nuclei >/dev/null 2>&1 && echo yes || echo no"):
        return "== nuclei sweep: nuclei not installed (skipped) =="
    raw = sb.bash(f"nuclei -u {url!r} -jsonl -silent -rl {int(rate)} -timeout 10 2>/dev/null "
                  f"| head -300", timeout=timeout)
    hits = _parse_nuclei(raw)
    if not hits:
        return "== nuclei sweep: no template matches =="
    lines = ["== nuclei sweep (severity-ranked: known CVEs / exposures / misconfigs) =="]
    lines += [f"  [{h['severity']}] {h['name']} — {h['matched']} ({h['template']})" for h in hits[:30]]
    return "\n".join(lines)


def nuclei_dast(sb, urls: str, rate: int = 8, timeout: int = 600) -> str:
    """ACTIVE parameter fuzzing via nuclei's DAST templates — the single biggest verify unlock the
    research found. Where nuclei_sweep matches KNOWN signatures, `-dast` actively FUZZES each URL's
    params/headers/path for reflected XSS, error-based SQLi, LFI/path-traversal, SSTI, open-redirect,
    CRLF and SSRF. Feed it param-bearing URLs (from endpoint_recon / JS mining); a bare origin fuzzes
    little. Runs THROUGH the enforced sandbox->proxy, so scope + rate limit still bind at the wire.

    Ceiling: OOB-only templates (blind SSRF/RCE that need an interactsh callback) can't fire under
    --enforce egress (the public interactsh server is unreachable) — use the `oob` tool for those.
    Reflection/error-based DAST (the bulk) fires fine. ponytail: no built-in crawler; feed URLs in.
    """
    if "yes" not in sb.bash("command -v nuclei >/dev/null 2>&1 && echo yes || echo no"):
        return "== nuclei -dast: nuclei not installed (skipped) =="
    targets = [u.strip() for u in (urls or "").replace(",", "\n").splitlines() if u.strip().startswith("http")]
    if not targets:
        return "== nuclei -dast: no http(s) URLs given (feed param-bearing URLs from endpoint_recon) =="
    listfile = "/tmp/dast_targets.txt"
    sb.bash("printf '%s\n' " + " ".join(repr(t) for t in targets[:50]) + f" > {listfile}")
    raw = sb.bash(f"nuclei -l {listfile} -dast -jsonl -silent -rl {int(rate)} -timeout 10 "
                  f"2>/dev/null | head -300", timeout=timeout)
    hits = _parse_nuclei(raw)
    if not hits:
        return f"== nuclei -dast: no fuzzing matches on {len(targets)} URL(s) (params may be unfuzzable or well-validated) =="
    lines = [f"== nuclei -dast (ACTIVE param fuzzing — {len(hits)} hit(s); these are CANDIDATES, confirm each) =="]
    lines += [f"  [{h['severity']}] {h['name']} — {h['matched']} ({h['template']})" for h in hits[:30]]
    lines.append("NOTE: DAST hits are leads — reproduce + prove impact before reporting (anti-slop).")
    return "\n".join(lines)

def crawl(sb, url: str, depth: int = 2, rate: int = 10, timeout: int = 300) -> str:
    """Actively CRAWL a live app with katana and return reachable URLs — prioritizing PARAM-BEARING
    ones, which are exactly what dast_scan fuzzes. Closes the discovery->verify loop that static
    JS-mining can't: mine_js_endpoints gives route *strings*; katana gives populated ?a=1&b=2 URLs
    an attacker can actually hit. No-op if katana isn't installed (image rebuild adds it). Runs
    THROUGH the enforced sandbox->proxy, so scope + rate bind at the wire.

    Returns two buckets: PARAM URLs (feed straight to dast_scan) and other in-scope URLs.
    ponytail: -jc (crawl linked JS) on, headless off (no browser dep in the wire path); turn on
    -hl later if a target is a JS-heavy SPA that needs a real renderer to enumerate."""
    if "yes" not in sb.bash("command -v katana >/dev/null 2>&1 && echo yes || echo no"):
        return "== crawl: katana not installed (skipped; rebuild the image to enable) =="
    raw = sb.bash(f"katana -u {url!r} -d {int(depth)} -jc -silent -rl {int(rate)} -timeout 10 "
                  f"2>/dev/null | head -400", timeout=timeout)
    urls = [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("http")]
    if not urls:
        return f"== crawl {url}: katana returned no URLs =="
    seen, params, others = set(), [], []
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        (params if "?" in u and "=" in u else others).append(u)
    lines = [f"== crawl {url}: {len(seen)} URL(s), {len(params)} param-bearing =="]
    if params:
        lines.append("PARAM URLs (feed these to dast_scan):")
        lines += [f"  {u}" for u in params[:40]]
    if others:
        lines.append("other in-scope URLs:")
        lines += [f"  {u}" for u in others[:25]]
    return "\n".join(lines)


def secret_scan(sb, url: str, max_bundles: int = 8, timeout: int = 240) -> str:
    """Hunt LIVE leaked credentials in the target's own JS/assets with trufflehog --only-verified —
    the highest single-bounty yield the research found. Downloads the homepage + linked JS bundles
    into the sandbox and scans them; --only-verified means trufflehog ACTIVELY checks each candidate
    against its provider (so a hit is a working key, not a regex guess). No-op if trufflehog isn't
    installed (image rebuild adds it). Runs THROUGH the enforced sandbox->proxy, so verification
    traffic + the fetch stay in-scope/rate-bound.

    Ceiling: scans linked static assets, not a full crawl — pair with `crawl` for reach. Only reports
    VERIFIED secrets (unverified regex noise is the slop programs are pausing bounties over)."""
    if "yes" not in sb.bash("command -v trufflehog >/dev/null 2>&1 && echo yes || echo no"):
        return "== secret_scan: trufflehog not installed (skipped; rebuild the image to enable) =="
    u = url.rstrip("/")
    fetch = _SECRET_FETCH.replace("__U__", u).replace("__N__", str(int(max_bundles)))
    raw = sb.bash(fetch, timeout=timeout)
    hits = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        det = o.get("DetectorName") or o.get("DetectorType") or "secret"
        red = (o.get("Redacted") or o.get("Raw") or "")[:40]
        hits.append("  [VERIFIED] %s: %s" % (det, red))
    if not hits:
        return "== secret_scan %s: no VERIFIED secrets in the fetched assets ==" % url
    return ("== secret_scan %s: %d VERIFIED secret(s) — LIVE credentials, confirm scope + report "
            "(do NOT exercise permissions beyond an identity check) ==\n" % (url, len(hits))
            + "\n".join(hits[:20]))


# file(1) / extension signals -> specialist key. First match wins.
_SIGNALS: list[tuple[str, str]] = [
    (r"ELF |PE32|Mach-O|executable", "rev"),
    (r"pcap|tcpdump|capture file", "forensics"),
    (r"image data|PNG|JPEG|bitmap|GIF|TIFF", "forensics"),
    (r"Zip archive|gzip|tar archive|7-zip|POSIX tar|RAR", "forensics"),
    (r"memory dump|Windows crash|ELF core", "forensics"),
    (r"PEM |RSA |OpenSSH|certificate|private key", "crypto"),
]
_CRYPTO_TEXT = re.compile(r"-----BEGIN|[A-Fa-f0-9]{64,}|^[A-Za-z0-9+/=]{40,}$", re.M)
_URL = re.compile(r"https?://[^\s\"'>]+")


def recon(sb, prompt: str = "") -> dict:
    """Return a brief: {listing, files:[{name,type}], target_url, suggested, notes}."""
    listing = sb.bash("ls -la")
    ftypes = sb.bash("file * 2>/dev/null").strip()
    files = []
    for line in ftypes.splitlines():
        if ":" in line:
            name, _, desc = line.partition(":")
            files.append({"name": name.strip(), "type": desc.strip()})

    # a small strings sample from any binary/data file, for the brief
    sample = sb.bash("for f in *; do [ -f \"$f\" ] && strings -n 6 \"$f\" 2>/dev/null "
                     "| head -20; done | head -60")

    suggested = _classify(prompt, ftypes, sample)
    target = _URL.search(prompt)
    target_url = target.group(0) if target else None
    return {
        "listing": listing.strip(),
        "files": files,
        "target_url": target_url,
        "suggested": suggested,
        "sample": sample.strip()[:2000],
        "probe": _deep_probe(sb, suggested, target_url).strip()[:3000],
    }


# Category-aware deterministic probes — cheap intel that primes the specialist.
# All tool-guarded (2>/dev/null / `|| true`) so a missing tool never errors.
_PROBES = {
    "rev": r"""for f in *; do [ -f "$f" ] || continue; if file "$f" | grep -qE 'ELF|PE32|Mach-O'; then echo "== $f =="; (checksec --file="$f" 2>/dev/null || pwn checksec "$f" 2>/dev/null) | head -8; readelf -h "$f" 2>/dev/null | grep -E 'Class|Machine|Type:'; fi; done""",
    "pwn": r"""for f in *; do [ -f "$f" ] || continue; if file "$f" | grep -qE 'ELF'; then echo "== $f =="; (checksec --file="$f" 2>/dev/null || pwn checksec "$f" 2>/dev/null) | head -8; fi; done""",
    "forensics": r"""for f in *; do [ -f "$f" ] || continue; case "$f" in *.pcap|*.pcapng) echo "== $f (protocols) =="; tshark -r "$f" -q -z io,phs 2>/dev/null | head -25;; *.png|*.bmp) echo "== $f (zsteg) =="; zsteg -a "$f" 2>/dev/null | head -12;; *.jpg|*.jpeg) echo "== $f (exif) =="; exiftool "$f" 2>/dev/null | grep -iE 'comment|artist|gps|software|xmp' | head;; *.zip|*.7z|*.tar*|*.gz) echo "== $f (contents) =="; 7z l "$f" 2>/dev/null | head -15;; esac; done""",
    "crypto": r"""for f in *; do [ -f "$f" ] || continue; case "$f" in *.txt|*.pem|*.pub|*.key|*.enc) echo "== $f =="; head -c 400 "$f"; echo;; esac; done; grep -rlE 'BEGIN (RSA|PUBLIC|PRIVATE)' . 2>/dev/null | head""",
    "web": "",  # target-driven; specialist probes the live host
    "misc": "",
}


def _web_recon(sb, url: str, lean: bool = False) -> str:
    """Best-in-class deterministic web enumeration — know what the target IS before
    exploiting. Systematic, ~one focused pass (not a spray): tech fingerprint, the
    live endpoint surface (status-coded), forms/params, well-known files, and API
    routes mined from linked JS. Hands the specialist a map so it targets, not flails.

    lean=True: ASSASSIN mode for STAGED re-fires on a new surface deeper in a chain —
    only the two free/passive fetches (fingerprint + WAF from headers, body mining for
    forms/params/linked endpoints). Skips the ~26-request well-known/endpoint brute-loops
    so re-reconning every surface of a chain stays quiet (~2 requests, not ~26).
    """
    u = url.rstrip("/")
    cmd = rf"""
U="{u}"
LEAN="{'1' if lean else ''}"
echo "== fingerprint (Server / framework / cookies) =="
HDR=$(curl -sSi -m 8 "$U/" 2>/dev/null)
echo "$HDR" | grep -iE '^(server|x-powered-by|x-aspnet|x-generator|via|set-cookie|content-type):' | head -12
echo "== WAF fingerprint (passive — from headers/cookies, no extra requests) =="
echo "$HDR" | grep -ioE 'cloudflare|cf-ray|akamaighost|x-akamai|sucuri|x-sucuri|incap_ses|visid_incap|x-iinfo|bigipserver|fortiwaf|barracuda|mod_security|awselb|x-sucuri-id|x-cdn' | sort -u | sed 's/^/  WAF signal: /' | head -6
echo "== homepage body (endpoints are often listed in text/JSON, not just links) =="
H=$(curl -s -m 8 "$U/" 2>/dev/null)
echo "$H" | head -c 600
echo ""
echo "== forms, params, comments =="
echo "$H" | grep -oiE '<form[^>]*action="[^"]*"[^>]*>|name="[^"]+"|<!--.*-->' | head -20
# mine any /path tokens mentioned anywhere in the body (catches text/JSON endpoint lists)
echo "$H" | grep -oiE '/[a-zA-Z0-9_/]{2,40}' | sort -u | head -25
echo "$H" | grep -oiE '(href|src)="[^"]+"' | sed -E 's/.*="([^"]+)".*/\1/' | grep -viE '\.(css|png|jpg|svg|ico|woff)' | sort -u | head -25
if [ -z "$LEAN" ]; then   # active enumeration — skipped on staged (assassin) re-fires
echo "== well-known / sensitive files (status) =="
for p in robots.txt sitemap.xml .well-known/security.txt .git/config .env package.json composer.json swagger.json openapi.json api-docs; do
  c=$(curl -s -o /dev/null -w "%{{http_code}}" -m 6 "$U/$p"); [ "$c" != "404" ] && echo "  $c  /$p"; done
echo "== endpoint surface (status-coded) =="
for p in api api/v1 api/v2 admin graphql rest login register users user products orders account metrics actuator/health debug .git; do
  c=$(curl -s -o /dev/null -w "%{{http_code}}" -m 6 "$U/$p"); [ "$c" != "404" ] && echo "  $c  /$p"; done
echo "== API routes mined from linked JS =="
for js in $(echo "$H" | grep -oiE 'src="[^"]+\.js"' | sed -E 's/src="([^"]+)".*/\1/' | head -3); do
  case "$js" in http*) J="$js";; /*) J="$U$js";; *) J="$U/$js";; esac
  curl -s -m 6 "$J" 2>/dev/null | grep -oiE '"/(api|rest|v[0-9])[a-zA-Z0-9_/-]*"|/api/[a-zA-Z0-9_/-]+' | tr -d '"' | sort -u | head -20
done
fi
"""
    brief = sb.bash(cmd)
    if not lean:                                      # recon wide: mine hidden endpoints from JS
        js = mine_js_endpoints(sb, u)
        if js:
            brief += "\n" + js
        if os.getenv("CTF_NUCLEI") == "1":            # opt-in known-CVE sweep for authorized targets
            brief += "\n" + nuclei_sweep(sb, u, rate=int(os.getenv("CTF_NUCLEI_RATE", "5")))
    return brief


def _deep_probe(sb, suggested: str, target: str | None = None) -> str:
    if suggested == "web":
        return _web_recon(sb, target) if target else ""
    cmd = _PROBES.get(suggested, "")
    return sb.bash(cmd) if cmd else ""


# Recon fingerprint -> the RAG queries most worth pre-loading. Recon already knows
# WHAT the target is; this turns that into the right playbook BEFORE the agent flails.
# (query, ) triples keyed by a substring found in the probe/sample/category.
_WEB_SIGNALS: list[tuple[str, str]] = [
    ("werkzeug", "ssti jinja2 server-side template injection python"),
    ("flask", "ssti jinja2 server-side template injection python"),
    ("django", "ssti python deserialization"),
    ("express", "prototype pollution nosql injection node"),
    ("nodejs", "prototype pollution nosql injection node"),
    ("node.js", "prototype pollution nosql injection node"),
    ("php", "lfi php filter wrapper deserialization object injection"),
    ("asp.net", "deserialization viewstate sql injection"),
    ("x-aspnet", "deserialization viewstate sql injection"),
    ("spring", "deserialization ssti spel"),
    ("graphql", "graphql introspection hidden mutation idor"),
    ("swagger", "api idor bola mass assignment"),
    ("openapi", "api idor bola mass assignment"),
    ("api-docs", "api idor bola mass assignment"),
    (".git", "source disclosure secrets in git"),
    (".env", "source disclosure secrets credentials"),
    ("jwt", "jwt forge alg none weak secret"),
    ("mongo", "nosql injection mongodb auth bypass"),
    ("waf signal", "waf filter evasion bypass inline comment encoding"),
]
# money bugs to seed for ANY web target, so the chain mindset is always primed.
_WEB_DEFAULT = ["exploit chain escalate primitives to critical",
                "idor bola broken access control object id",
                "sql injection union blind", "ssrf cloud metadata bypass"]
_CAT_QUERY = {
    "rev": "reverse engineering decompile angr solve check",
    "pwn": "rop stack overflow format string ret2libc pwntools",
    "crypto": "rsa attack classical cipher hash cracking",
    "forensics": "forensics stego binwalk pcap tshark memory",
}


def _stack_from(b: str) -> str:
    for k in ("werkzeug", "flask", "django", "express", "node", "php", "asp.net",
              "spring", "rails", "gunicorn", "tomcat", "nginx", "apache"):
        if k in b:
            return k
    return ""


def profile_surface(brief: str) -> dict:
    """Fingerprint -> target ARCHETYPE prior, the way a real operator picks a playbook before
    touching anything (OWASP WSTG 'map before you probe'; ATT&CK Reconnaissance). Returns
    {archetype, stack, hunt[], skip[]}: what this KIND of target is, the ranked techniques that
    APPLY, and the ones to SKIP so we don't spray wordlists/LFI/CMS paths at a 4-route JSON API.
    Advisory — a prior the agent holds loosely, not a gate; when the ranked tree is exhausted it
    should widen out rather than treat 'skip' as forbidden."""
    b = (brief or "").lower()
    stack = _stack_from(b)

    def prof(a, hunt, skip):
        return {"archetype": a, "stack": stack, "hunt": hunt, "skip": skip}

    if "graphql" in b:
        return prof("GraphQL API",
                    ["introspection {__schema}", "hidden queries/mutations, call unauth",
                     "IDOR via node global ids", "alias batching to bypass rate limits"],
                    ["REST/directory wordlist brute-force", "server-side template hunting",
                     "CMS/WordPress paths"])
    if any(s in b for s in ("wp-content", "wp-json", "wordpress", "drupal", "joomla",
                            "x-generator", "x-drupal")):
        return prof("CMS",
                    ["plugin/theme version -> known CVEs", "xmlrpc.php abuse",
                     "user enumeration (?author=/wp-json/wp/v2/users)", "weak/default admin creds"],
                    ["custom-framework SSTI", "GraphQL introspection", "generic API mass-assignment"])
    api = ("application/json" in b or "/api" in b or b.strip().startswith("{")
           or '"error"' in b or '"data"' in b or '"message"' in b)
    forms = "<form" in b
    spa = ('id="root"' in b or 'id="app"' in b or "bundle.js" in b or "main." in b
           or "__next" in b or "ng-app" in b)
    if spa and api:
        return prof("SPA + JSON API",
                    ["the /api surface: IDOR/BOLA on object ids", "mass assignment (extra fields)",
                     "auth/JWT & token handling", "CORS misconfig (credentialed wildcard)"],
                    ["server-side template injection on pages", "directory brute-force for pages",
                     "LFI on page params"])
    if api and not forms:
        return prof("REST-JSON API",
                    ["IDOR/BOLA on every object id", "mass assignment (POST/PUT extra fields)",
                     "JWT (alg:none / weak secret / kid)", "param injection SQLi/NoSQLi + WAF evasion",
                     "rate-limit & business-logic abuse"],
                    ["directory/wordlist brute-force", ".php/.env/CMS path spraying",
                     "LFI file-read hunting", "reflected/stored XSS"])
    if forms or stack in ("php", "flask", "django", "rails", "spring", "werkzeug"):
        return prof("Server-rendered app",
                    ["SQLi in forms/query params", "SSTI in reflected fields (name/email/report)",
                     "LFI / path traversal", "file upload -> RCE", "auth/session flaws"],
                    ["GraphQL introspection", "JWT alg-confusion", "API mass-assignment"])
    return prof("Generic web",
                ["map endpoints from links/JS first", "injection in any reflected param",
                 "auth & access control", "known-CVE by fingerprint"],
                ["blind wordlist spraying before the surface is mapped"])


def _hint_queries(r: dict) -> list[str]:
    cat = r.get("suggested")
    if cat == "web":
        probe = ((r.get("probe") or "") + " " + (r.get("sample") or "")).lower()
        qs = [q for key, q in _WEB_SIGNALS if key in probe]
        qs += _WEB_DEFAULT
        # dedupe, keep order, cap so the prompt stays lean
        seen, out = set(), []
        for q in qs:
            if q not in seen:
                seen.add(q); out.append(q)
        return out[:5]
    if cat == "crypto":
        s = (r.get("sample") or "").lower()
        if "begin" in s or "rsa" in s:
            return ["rsa attack factor public key small exponent"]
        return [_CAT_QUERY["crypto"]]
    return [_CAT_QUERY[cat]] if cat in _CAT_QUERY else []


def playbook_text(r: dict) -> str:
    """Proactively retrieve the RAG cards matching what recon found, so the specialist
    opens with the right technique already in hand. Fingerprint-scoped (not the whole
    KB) to stay lean. Disable with CTF_PLAYBOOK=0 (bench A/B)."""
    if os.getenv("CTF_PLAYBOOK", "1") == "0":
        return ""
    try:
        from knowledge_base import get_kb
        kb = get_kb()
    except Exception:
        return ""
    seen, cards = set(), []
    for q in _hint_queries(r):
        for h in kb.search(q, k=2):
            if h["title"] not in seen:
                seen.add(h["title"]); cards.append(h)
    cards = cards[:4]
    if not cards:
        return ""
    def _strip_heading(t: str) -> str:  # chunk text starts with its own ## title
        return re.sub(r"^#{1,6}\s.*\n", "", t, count=1)
    body = "\n\n".join(f"### {h['title']}\n{_strip_heading(h['text'])[:700]}"
                       for h in cards)
    return ("\n\n## Recon-matched playbook (auto-loaded for THIS target; "
            "search_knowledge for more)\n" + body)


def _classify(prompt: str, ftypes: str, sample: str) -> str:
    if _URL.search(prompt):
        return "web"
    for pat, cat in _SIGNALS:
        if re.search(pat, ftypes):
            return cat
    if _CRYPTO_TEXT.search(sample):
        return "crypto"
    return "misc"


def demo() -> None:
    assert _classify("go pwn http://host:1234/", "", "") == "web"
    assert _classify("", "chall: ELF 64-bit LSB executable", "") == "rev"
    assert _classify("", "dump.pcap: pcap capture file", "") == "forensics"
    assert _classify("", "photo.png: PNG image data", "") == "forensics"
    assert _classify("", "key.pem: unknown", "-----BEGIN RSA PRIVATE KEY-----") == "crypto"
    assert _classify("just a riddle", "notes.txt: ASCII text", "hello world") == "misc"
    # recon->playbook: a Flask fingerprint should pre-load the SSTI card; pwn -> ROP
    web = {"suggested": "web", "probe": "Server: Werkzeug/2.0 Python/3.9", "sample": ""}
    pb = playbook_text(web).lower()
    assert "template" in pb and "chain" in pb, f"web playbook missed: {pb[:200]}"
    pwn = {"suggested": "pwn", "probe": "", "sample": ""}
    assert "rop" in playbook_text(pwn).lower(), "pwn playbook missed ROP"
    # a passive WAF fingerprint auto-loads the evasion playbook
    wafbrief = {"suggested": "web", "probe": "  WAF signal: cloudflare", "sample": ""}
    assert any("waf" in q for q in _hint_queries(wafbrief)), "WAF signal didn't trigger evasion query"
    assert "evasion" in playbook_text(wafbrief).lower(), "WAF playbook missed evasion card"
    assert playbook_text({"suggested": "web"}) != ""
    os.environ["CTF_PLAYBOOK"] = "0"
    assert playbook_text(web) == "", "CTF_PLAYBOOK=0 should disable"
    os.environ.pop("CTF_PLAYBOOK")
    # nuclei_dast: URL filtering + graceful no-ops, driven by a fake sandbox
    class _FakeSB:
        def __init__(self, has_nuclei): self.has = has_nuclei; self.seen = []
        def bash(self, cmd, timeout=None):
            self.seen.append(cmd)
            if "command -v nuclei" in cmd: return "yes\n" if self.has else "no\n"
            if cmd.startswith("nuclei -l"): return ""      # no matches
            return ""
    assert "not installed" in nuclei_dast(_FakeSB(False), "http://x/a?b=1")
    assert "no http(s) URLs" in nuclei_dast(_FakeSB(True), "not-a-url, ftp://x")
    fb = _FakeSB(True); out = nuclei_dast(fb, "http://x/a?b=1, http://x/c?d=2")
    assert "no fuzzing matches on 2 URL" in out, out
    assert any(c.startswith("printf") and "http://x/a?b=1" in c for c in fb.seen)
    # crawl: no-op when katana absent; param vs non-param bucketing when present
    class _KSB:
        def __init__(self, has, urls): self.has=has; self.urls=urls
        def bash(self, cmd, timeout=None):
            if "command -v katana" in cmd: return "yes\n" if self.has else "no\n"
            return self.urls
    assert "not installed" in crawl(_KSB(False, ""), "http://x/")
    cout = crawl(_KSB(True, "http://x/a?id=1\nhttp://x/about\nhttp://x/a?id=1\n"), "http://x/")
    assert "1 param-bearing" in cout and "http://x/a?id=1" in cout, cout   # deduped, bucketed
    assert "http://x/about" in cout
    # secret_scan: no-op when absent; only VERIFIED trufflehog hits reported
    class _TSB:
        def __init__(self, has, out): self.has=has; self.out=out; self.seen=[]
        def bash(self, cmd, timeout=None):
            self.seen.append(cmd)
            if "command -v trufflehog" in cmd: return "yes" if self.has else "no"
            return self.out
    assert "not installed" in secret_scan(_TSB(False, ""), "http://x/")
    tsb = _TSB(True, '{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA..RED"}')
    so = secret_scan(tsb, "http://x/")
    assert "VERIFIED" in so and "AWS" in so, so
    assert any("trufflehog filesystem" in c and "http://x/" in c for c in tsb.seen)
    assert "no VERIFIED secrets" in secret_scan(_TSB(True, "no json here"), "http://x/")
    print("recon.py ok")


def brief_text(r: dict) -> str:
    """Render the brief for injection into the specialist's opening prompt."""
    lines = ["## Recon brief (gathered before you started)",
             "Files present:"]
    lines += [f"  - {f['name']}: {f['type']}" for f in r["files"]] or ["  (none detected)"]
    if r["target_url"]:
        lines.append(f"Target URL: {r['target_url']}")
    if r.get("probe"):
        lines.append(f"Category probe:\n{r['probe']}")
    if r["sample"]:
        lines.append(f"Notable strings:\n{r['sample']}")
    return "\n".join(lines) + playbook_text(r)


if __name__ == "__main__":
    demo()
