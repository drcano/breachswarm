"""Chain-finder — compose confirmed primitives into criticals ("never report a primitive alone").

The #1 architectural gap the research found: criticals are CHAINS, not single bugs. We already bank
individual primitives (leads/facts). This matches them against canonical chain templates and tells
the agent which primitives combine into a critical and what the next hop is. A lone SSRF/IDOR/
open-redirect is a LEAD, not a finding, until it's chained or its impact is proven.

Pure logic — the agent calls find_chains over its lead backlog; no LLM here.
"""
from __future__ import annotations

import re

# primitive-type -> regex over a lead/fact observation. First match wins.
_PRIMITIVES = [
    ("ssrf",           r"\bssrf\b|server-side request|fetch(es|ing)?\s+.*url|webhook|redirect[- ]follow|url[- ]fetch"),
    ("open-redirect",  r"open[- ]redirect|redirect_uri|redirects? to|\?returnurl|\bnext=|location header"),
    ("xss",            r"\bxss\b|cross-site script|onerror=|<script|dom[- ]based|stored script"),
    ("idor",           r"\bidor\b|\bbola\b|object[- ]level|cross[- ](account|user|tenant)|account_id|sequential id|guessable id"),
    ("admin",          r"\badmin\b|privileged|dfadmin|/admin|internal (panel|app)|superuser|back[- ]office"),
    ("secret",         r"secret|api[-_ ]?key|token leak|leaked (key|token|cred)|\.env\b|\.git\b|hardcoded|credential"),
    ("oauth",          r"\boauth\b|\boidc\b|/authorize|\bsso\b|openid|id_token|access_token flow"),
    ("graphql",        r"graphql|/graphql|introspection|node id"),
    ("exposed-origin", r"exposed[- ]origin|not behind (the )?(waf|cdn|cloudflare)|waf[- ]bypass|origin ip"),
    ("upload",         r"\bupload\b|file write|arbitrary file|multipart.*file"),
    ("path-traversal", r"path traversal|\.\./|\blfi\b|directory traversal|%2e%2e"),
    ("auth-bypass",    r"auth(entication|z)? bypass|login bypass|missing auth|unauthenticated access"),
    ("xxe",            r"\bxxe\b|xml external entity|external entity|<!entity"),
]

# each template: primitives it needs, the resulting impact, and the concrete next hop.
CHAIN_TEMPLATES = [
    ("ssrf", "SSRF→cloud-metadata→IAM takeover", ["ssrf"],
     "Critical: infra/account takeover via stolen cloud creds",
     "point the confirmed SSRF at 169.254.169.254/latest/meta-data/ and metadata.google.internal "
     "(Metadata-Flavor: Google) via ssrf_recon; pull IAM/instance creds, then enumerate internal ranges"),
    ("open-redirect,oauth", "open-redirect→OAuth code theft→ATO", ["open-redirect", "oauth"],
     "Critical: account takeover via stolen OAuth code/token",
     "set the OAuth redirect_uri to the open-redirect that bounces to an oob collaborator; capture the "
     "leaked code/token in the callback"),
    ("xss,oauth", "XSS→OAuth/session theft→ATO", ["xss", "oauth"],
     "Critical: account takeover via session/token exfil",
     "land the XSS in an authenticated context and exfil the session/token to the oob collaborator; "
     "confirm execution with browser_verify"),
    ("idor,admin", "IDOR→admin object→function-level→config/RCE", ["idor", "admin"],
     "Critical: privilege escalation to admin functions",
     "use the IDOR to reach an admin-owned object, then replay its state-changing/function-level "
     "requests as the low-priv user via authz_matrix (write-path)"),
    ("secret", "secret-exposure→auth bypass→data access", ["secret"],
     "High/Critical: authenticated access via a leaked credential",
     "do ONE minimal auth check with the leaked key (identity only), confirm it is live, then STOP and "
     "report — do not exercise its permissions"),
    ("graphql,idor", "GraphQL introspection→BOLA", ["graphql", "idor"],
     "High: read/modify other users' data via GraphQL",
     "introspect the schema, then hit every query/mutation with a swapped global node id via "
     "authz_matrix; test alias/batching to bypass rate limits"),
    ("upload,path-traversal", "upload+path-traversal→RCE", ["upload", "path-traversal"],
     "Critical: remote code execution via file write outside the intended dir",
     "chain the traversal into the upload path to write to a web-served/executable location; prove "
     "with a harmless fixed-string check, then STOP"),
    ("xxe", "XXE→SSRF/file-read", ["xxe"],
     "High/Critical: internal file read or SSRF via XML parsing",
     "use the XXE to read a benign file or hit the oob collaborator (blind XXE); do not exfil secrets"),
    ("exposed-origin", "exposed-origin→WAF bypass", ["exposed-origin"],
     "Enabler: reach protected surface the WAF/CDN was shielding",
     "hit the origin directly (Host header / direct IP) to bypass the WAF and re-test classes that the "
     "edge was blocking"),
]


def classify_lead(text: str) -> str:
    """Map a lead/fact observation to a primitive-type, or '' if none matches."""
    low = (text or "").lower()
    for name, pat in _PRIMITIVES:
        if re.search(pat, low):
            return name
    return ""


def find_chains(leads) -> list[dict]:
    """leads = list of observation strings or dicts with 'observation'. Returns proposed chains,
    READY (all primitives present) first, then ONE-HOP-AWAY (one primitive missing)."""
    present = set()
    for l in leads or []:
        obs = l.get("observation", "") if isinstance(l, dict) else str(l)
        p = classify_lead(obs)
        if p:
            present.add(p)
    out = []
    for _key, name, req, impact, nxt in CHAIN_TEMPLATES:
        need = set(req)
        have = need & present
        missing = need - present
        if not missing:
            out.append({"status": "READY", "chain": name, "impact": impact,
                        "have": sorted(have), "missing": [], "next": nxt})
        elif len(missing) == 1 and len(need) > 1:
            out.append({"status": "ONE-HOP", "chain": name, "impact": impact,
                        "have": sorted(have), "missing": sorted(missing), "next": nxt})
    out.sort(key=lambda c: (c["status"] != "READY", -len(c["have"])))
    return out


def render(chains: list[dict]) -> str:
    if not chains:
        return "chain_scan: no chains proposable yet from the banked primitives."
    lines = []
    for c in chains:
        tag = "▶ READY" if c["status"] == "READY" else f"○ one hop (need: {','.join(c['missing'])})"
        lines.append(f"{tag} — {c['chain']}\n    impact: {c['impact']}\n    have: {','.join(c['have'])}"
                     f"\n    NEXT: {c['next']}")
    return "CHAIN SCAN — never report a primitive alone; pursue these:\n" + "\n".join(lines)


def demo() -> None:
    assert classify_lead("confirmed SSRF: server fetches attacker url") == "ssrf"
    assert classify_lead("open-redirect via redirect_uri param") == "open-redirect"
    assert classify_lead("just a boring 404") == ""
    # SSRF alone -> a READY single-primitive escalation template
    c = find_chains(["confirmed blind SSRF on webhook param"])
    assert any(x["chain"].startswith("SSRF") and x["status"] == "READY" for x in c), c
    # open-redirect + oauth -> READY ATO chain
    c2 = find_chains([{"observation": "open redirect on /login?next="},
                      {"observation": "oauth authorize flow at /authorize"}])
    assert any("OAuth code theft" in x["chain"] and x["status"] == "READY" for x in c2), c2
    # only oauth -> the ATO chain shows ONE-HOP (missing open-redirect)
    c3 = find_chains(["oauth /authorize endpoint present"])
    hop = [x for x in c3 if "OAuth code theft" in x["chain"]]
    assert hop and hop[0]["status"] == "ONE-HOP" and hop[0]["missing"] == ["open-redirect"], c3
    assert "READY" in render(find_chains(["ssrf confirmed"]))
    print("chain.py ok")


if __name__ == "__main__":
    demo()
