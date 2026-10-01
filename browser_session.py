"""Authenticated browser session — an executable exploit PRIMITIVE (the #2 lever: auth context).

browser_verify renders ONE page host-side, LOGGED-OUT, with Chrome --dump-dom. It is blind to the
whole authenticated, JS-heavy surface — exactly where the bugs the research says we miss actually
live (post-login SPA routes, stored/DOM XSS behind auth, and the XHR API the app calls that no
static crawl sees). This drives a real headless Chromium via Playwright INSIDE the sandbox (the
image already ships `playwright install chromium`), so it runs THROUGH the enforced egress proxy —
scope + rate still bind at the wire — while carrying the session auth.

It carries auth three ways (use any/all): request headers (Bearer/API key), cookies, and
localStorage (many SPAs keep the JWT there, not in a cookie). It returns: the final URL after any
client redirect, the post-JS DOM (trimmed), same-origin app links, and — the killer feature — every
XHR/fetch the authenticated page fired (the REAL API surface to attack next). Optional marker/
live_hint check makes it a superset of browser_verify for AUTHENTICATED stored/DOM XSS.

ponytail: one-shot render, not a stateful driver held across tool calls. If a bug needs a multi-step
click-through (add to cart -> checkout), pass `actions` (a short list of click/fill/wait steps); for
anything richer, that's a real CDP session — graduate then, not now.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import urlparse


def parse_cookies(raw) -> list:
    """'a=b; c=d' (or a dict, or a list) -> [{'name','value'}]. Domain/path are attached at run time
    from the target URL so the caller only needs name=value pairs."""
    if not raw:
        return []
    if isinstance(raw, dict):
        return [{"name": k, "value": str(v)} for k, v in raw.items()]
    if isinstance(raw, list):
        out = []
        for it in raw:
            if isinstance(it, dict) and "name" in it:
                out.append({"name": it["name"], "value": str(it.get("value", ""))})
        return out
    out = []
    for part in str(raw).split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            if k.strip():
                out.append({"name": k.strip(), "value": v.strip()})
    return out


def interesting_xhr(pairs: list, origin: str, limit: int = 40) -> list:
    """From [(method,url)] captured by the browser, keep the API-ish requests (non-GET, or a path
    that looks like an endpoint, or JSON-y), dedup by (method, path-without-query), same-origin or
    api-subdomain first. These are the REAL endpoints the app talks to — the attack surface."""
    host = urlparse(origin).netloc
    root = ".".join(host.split(".")[-2:]) if host else ""
    seen, out = set(), []
    STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2",
              ".gif", ".map", ".webp", ".mp4")
    for method, url in pairs:
        p = urlparse(url)
        path = p.path or "/"
        if any(path.lower().endswith(e) for e in STATIC):
            continue
        same = (root and root in p.netloc)
        apiish = (method.upper() != "GET" or "/api" in path.lower() or "graphql" in path.lower()
                  or "/v1" in path.lower() or "/v2" in path.lower() or "?" in url)
        if not (same or apiish):
            continue
        key = (method.upper(), p.netloc, path)
        if key in seen:
            continue
        seen.add(key)
        out.append(f"{method.upper():6} {p.scheme}://{p.netloc}{path}" + ("?…" if p.query else ""))
        if len(out) >= limit:
            break
    return out


def verdict(dom: str, marker: str, live_hint: str = "") -> str:
    """Same execution/escaping logic as browser_verify — reused so there's ONE XSS oracle."""
    dom = dom or ""
    if marker and marker in dom:
        return f"XSS EXECUTED (authenticated) — marker '{marker}' present in the post-JS DOM. Confirmed."
    if live_hint and live_hint in dom:
        return (f"PARSED AS LIVE HTML — '{live_hint}' rendered as markup (not escaped) but the "
                "execution marker did not appear. Likely XSS; adjust the payload's side effect.")
    return ""


def _script(params: dict) -> str:
    """The primitive as a self-contained Playwright script run inside the sandbox."""
    return "import json,sys,os\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
from playwright.sync_api import sync_playwright
xhr=[]; final=""; dom=""; links=[]
def onreq(r):
    try: xhr.append([r.method, r.url])
    except Exception: pass
# Under --enforce the container's ONLY egress is the proxy (HTTP_PROXY env). Chromium does NOT read
# that env on its own, so pass it explicitly — otherwise the browser has no route out (or, in direct
# mode, would dodge scope). No proxy env => direct (network=True) run.
_prox=os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
_launch={"args":["--no-sandbox","--disable-gpu"]}
if _prox: _launch["proxy"]={"server":_prox}
with sync_playwright() as pw:
    b=pw.chromium.launch(**_launch)
    ctx=b.new_context(extra_http_headers=P.get("headers",{}) or {}, ignore_https_errors=True)
    if P.get("cookies"):
        cs=[]
        for c in P["cookies"]:
            c=dict(c); c["url"]=P["url"]; cs.append(c)
        try: ctx.add_cookies(cs)
        except Exception as e: print("COOKIE_WARN:"+str(e)[:100])
    pg=ctx.new_page()
    st=P.get("storage") or {}
    if st:
        pg.add_init_script("(()=>{try{var s=%s;for(var k in s)localStorage.setItem(k,s[k]);}catch(e){}})()"%json.dumps(st))
    pg.on("request", onreq)
    T=int(P.get("timeout",25))*1000
    try:
        pg.goto(P["url"], wait_until=P.get("wait","networkidle"), timeout=T)
    except Exception as e:
        print("GOTO_WARN:"+str(e)[:120])
    for a in (P.get("actions") or []):
        try:
            k=a.get("do"); sel=a.get("sel","")
            if k=="click": pg.click(sel, timeout=5000)
            elif k=="fill": pg.fill(sel, a.get("val",""), timeout=5000)
            elif k=="wait": pg.wait_for_timeout(int(a.get("ms",1000)))
        except Exception as e: print("ACTION_WARN:"+str(e)[:100])
    try:
        final=pg.url; dom=pg.content()
        links=pg.eval_on_selector_all("a[href]","els=>els.map(e=>e.href)")
    except Exception as e: print("READ_WARN:"+str(e)[:100])
    b.close()
print("BSESSION_JSON:"+json.dumps({"final":final,"dom":dom[:8000],"links":links[:120],"xhr":xhr}))
'''


def run(sb, args: dict) -> str:
    url = args.get("url") or ""
    if not url.startswith("http"):
        return "browser_session error: 'url' must be an absolute http(s) URL."
    headers = {}
    h = args.get("headers")
    if isinstance(h, dict):
        headers = {str(k): str(v) for k, v in h.items()}
    elif isinstance(h, str) and ":" in h:                 # 'Authorization: Bearer x' single header
        for line in h.replace("\\n", "\n").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
    storage = args.get("storage")
    if isinstance(storage, str) and storage.strip():
        try:
            storage = json.loads(storage)
        except Exception:
            storage = {}
    actions = args.get("actions")
    if isinstance(actions, str) and actions.strip():
        try:
            actions = json.loads(actions)
        except Exception:
            actions = []
    params = {"url": url, "headers": headers, "cookies": parse_cookies(args.get("cookies")),
              "storage": storage if isinstance(storage, dict) else {},
              "actions": actions if isinstance(actions, list) else [],
              "timeout": int(args.get("timeout") or 25),
              "wait": args.get("wait") or "networkidle"}
    b64 = base64.b64encode(_script(params).encode()).decode()
    out = sb.bash(f"echo {b64} | base64 -d | python3 -", timeout=int(params["timeout"]) + 30)
    if "playwright" in out.lower() and ("no module named" in out.lower()
                                        or "not found" in out.lower() or "executable doesn" in out.lower()):
        return ("browser_session: Playwright/chromium unavailable in the sandbox — rebuild the image "
                "(Dockerfile runs `playwright install chromium`).\n" + out[:300])
    payload = None
    for line in out.splitlines():
        if line.startswith("BSESSION_JSON:"):
            try:
                payload = json.loads(line[len("BSESSION_JSON:"):])
            except Exception:
                payload = None
    if payload is None:
        return "browser_session: no render captured — sandbox output:\n" + out[:600]
    origin = params["url"]
    endpoints = interesting_xhr(payload.get("xhr", []), origin)
    app_links = sorted({l for l in payload.get("links", []) if l.startswith("http")})[:30]
    lines = [f"BROWSER_SESSION {origin} -> final {payload.get('final','')}"]
    xv = verdict(payload.get("dom", ""), args.get("marker", ""), args.get("live_hint", ""))
    if xv:
        lines.append("‼ " + xv)
    if endpoints:
        lines.append(f"== XHR/fetch API surface the authenticated page called ({len(endpoints)}) — "
                     "the REAL endpoints; attack these ==")
        lines += ["  " + e for e in endpoints]
    if app_links:
        lines.append(f"== same-scope app links ({len(app_links)}) ==")
        lines += ["  " + l for l in app_links]
    warns = [ln for ln in out.splitlines() if ln.endswith("_WARN") or "_WARN:" in ln]
    if warns:
        lines.append("(" + "; ".join(w[:80] for w in warns[:4]) + ")")
    if not endpoints and not app_links and not xv:
        lines.append("(rendered, but no XHR/links/XSS-marker surfaced — page may need auth or an action)")
    return "\n".join(lines)


def demo() -> None:
    assert parse_cookies("session=abc; token=xyz") == [
        {"name": "session", "value": "abc"}, {"name": "token", "value": "xyz"}]
    assert parse_cookies({"a": 1}) == [{"name": "a", "value": "1"}]
    assert parse_cookies("") == []
    # XHR filtering: keep API/non-GET/same-origin, drop static, dedup by path
    pairs = [["GET", "https://app.x.com/static/main.js"],
             ["GET", "https://app.x.com/api/v1/users?page=1"],
             ["POST", "https://app.x.com/api/v1/orders"],
             ["GET", "https://app.x.com/api/v1/users?page=2"],       # dup path -> collapsed
             ["GET", "https://cdn.other.com/lib.css"],
             ["GET", "https://app.x.com/graphql"]]
    eps = interesting_xhr(pairs, "https://app.x.com/")
    assert any("POST" in e and "/api/v1/orders" in e for e in eps), eps
    assert sum("/api/v1/users" in e for e in eps) == 1, eps           # deduped
    assert not any("main.js" in e or "lib.css" in e for e in eps), eps
    assert any("/graphql" in e for e in eps), eps
    # XSS oracle reused
    assert "EXECUTED" in verdict('<html data-x="M1">', "M1")
    assert verdict("<html>escaped</html>", "M1") == ""
    # run() no-op-ish path with a fake sandbox that reports playwright missing
    class SB:
        def bash(self, c, timeout=None): return "ModuleNotFoundError: No module named 'playwright'"
    assert "Playwright/chromium unavailable" in run(SB(), {"url": "https://app.x.com/"})
    class SB2:
        def bash(self, c, timeout=None):
            return 'BSESSION_JSON:' + json.dumps({"final": "https://app.x.com/home",
                    "dom": '<html data-x="MARK">ok</html>', "links": ["https://app.x.com/settings"],
                    "xhr": [["POST", "https://app.x.com/api/v1/orders"]]})
    r = run(SB2(), {"url": "https://app.x.com/", "marker": "MARK"})
    assert "XSS EXECUTED" in r and "/api/v1/orders" in r and "/settings" in r, r
    print("browser_session.py ok")


if __name__ == "__main__":
    demo()
