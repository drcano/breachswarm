"""ATT&CK technique registry + blue-team scorecard.

The purple-team deliverable: every action the agent takes is classified to a MITRE ATT&CK
technique and the DEFENSIVE CONTROL it exercises, then rolled up into a scorecard that tells
the defender what their controls caught vs missed. A stealth run's value isn't the access —
it's the sentence "your WAF blocked path traversal but MISSED evaded UNION SQLi."

`classify()` is signature-based (maps an observed payload to techniques); `scorecard()`
consumes (payload, outcome) events — where the TARGET's own response says whether the control
caught it (a 403/WAF-block = detected; a 200 to an evaded payload = a detection gap).
"""
from __future__ import annotations

import re
from collections import defaultdict

# attack_id -> (name, tactic, control it tests). Real ATT&CK technique ids.
TECHNIQUES = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access", "WAF/IDS"),
    "T1059": ("Command & Scripting Interpreter", "Execution", "EDR/WAF"),
    "T1078": ("Valid Accounts / privilege abuse", "Priv. Escalation", "IAM/authz"),
    "T1552": ("Unsecured Credentials", "Credential Access", "secrets scanning/DLP"),
    "T1083": ("File & Directory Discovery", "Discovery", "WAF/EDR"),
    "T1213": ("Data from Information Repositories", "Collection", "DLP/authz"),
    "T1071": ("Application-Layer Protocol (C2/SSRF egress)", "Command & Control", "egress/NDR"),
}

# signature -> (attack_id, human label for the specific technique variant)
_SIGS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"union[\s/*]+select|information_schema|\bor\b\s+1=1|sleep\(|pg_sleep", re.I), "T1190", "SQL injection"),
    (re.compile(r"\$ne\b|\$regex|\$where|\$gt\b", re.I), "T1190", "NoSQL injection"),
    (re.compile(r"\{\{.*\}\}|__globals__|\$\{.*\}|<%=|render_template_string", re.I), "T1190", "SSTI / template injection"),
    (re.compile(r"(?:;|\||&&|\$\(|`)\s*(id|whoami|cat |uname|curl |wget )", re.I), "T1059", "OS command injection"),
    (re.compile(r"\.\./|%2e%2e|/etc/passwd|php://|\.\.%2f", re.I), "T1083", "path traversal / LFI"),
    (re.compile(r"169\.254\.169\.254|2852039166|0xa9fea9fe|metadata\.google|latest/meta-data", re.I), "T1071", "SSRF → cloud metadata"),
    (re.compile(r'"?(role|isadmin|is_admin|is_staff|account_type|verified)"?\s*[:=]\s*"?(admin|true|1)', re.I), "T1078", "mass assignment / priv-esc"),
    (re.compile(r'"alg"\s*:\s*"none"|jwt|eyJ[A-Za-z0-9_-]+\.', re.I), "T1552", "JWT forge / weak secret"),
    (re.compile(r"/\.git/|/\.env\b|\.js\.map|id_rsa|aws_secret|\.sql\b", re.I), "T1552", "exposed secrets / source"),
    (re.compile(r"/rest/basket/|/api/orders/\d|/users/\d|node\(id:", re.I), "T1213", "IDOR / BOLA object access"),
]


def classify(payload: str) -> list[tuple[str, str]]:
    """Map an observed request/payload to (attack_id, variant-label) pairs it matches."""
    out = []
    for rx, tid, label in _SIGS:
        if rx.search(payload or ""):
            out.append((tid, label))
    # dedupe, preserve order
    seen, uniq = set(), []
    for t in out:
        if t not in seen:
            seen.add(t); uniq.append(t)
    return uniq


def outcome_from(status: int | None, body: str = "") -> tuple[bool, bool]:
    """Derive (blocked, success) from the target's own response — the ground truth for
    whether a control caught the technique. blocked = the control rejected it (WAF 403 /
    block text); success = it went through (2xx, no block)."""
    low = (body or "").lower()
    blocked = status == 403 or any(s in low for s in
              ("waf", "request blocked", "forbidden", "suspicious", "not allowed", "malicious"))
    success = (status is not None and 200 <= status < 300) and not blocked
    return blocked, success


def scorecard(events: list[dict]) -> dict:
    """events: [{payload, blocked, success}]. Roll up per (technique, control):
    attempts, blocked-by-control, evaded-and-succeeded (== a DETECTION GAP)."""
    agg: dict = defaultdict(lambda: {"attempts": 0, "blocked": 0, "missed": 0, "labels": set()})
    for e in events:
        for tid, label in classify(e.get("payload", "")):
            row = agg[tid]
            row["attempts"] += 1
            row["labels"].add(label)
            if e.get("blocked"):
                row["blocked"] += 1
            elif e.get("success"):
                row["missed"] += 1
    out = {}
    for tid, row in agg.items():
        name, tactic, control = TECHNIQUES.get(tid, ("?", "?", "?"))
        out[tid] = {**row, "labels": sorted(row["labels"]), "name": name,
                    "tactic": tactic, "control": control,
                    "detection_gap": row["missed"] > 0}
    return out


def render(sc: dict) -> str:
    """Blue-team scorecard as markdown."""
    if not sc:
        return "_No classified techniques observed._"
    lines = ["| ATT&CK | Technique | Control tested | Attempts | Blocked | **Missed** | Verdict |",
             "|---|---|---|---|---|---|---|"]
    gaps = 0
    for tid, r in sorted(sc.items()):
        gaps += 1 if r["detection_gap"] else 0
        verdict = "🔴 DETECTION GAP" if r["detection_gap"] else ("🟢 caught" if r["blocked"] else "⚪ n/a")
        lines.append(f"| {tid} | {', '.join(r['labels'])} | {r['control']} | {r['attempts']} "
                     f"| {r['blocked']} | {r['missed']} | {verdict} |")
    lines.append(f"\n**{gaps} control gap(s)** across {len(sc)} techniques exercised.")
    return "\n".join(lines)


def demo() -> None:
    events = [
        {"payload": "category=1' UNION/**/SELECT ...", "blocked": False, "success": True},   # evaded SQLi missed
        {"payload": "category=1' UNION SELECT ...", "blocked": True, "success": False},       # raw SQLi caught
        {"payload": "url=http://2852039166/latest/meta-data/", "blocked": False, "success": True},  # SSRF missed
        {"payload": "GET /rest/basket/2", "blocked": False, "success": True},                 # IDOR missed
    ]
    assert ("T1190", "SQL injection") in classify(events[0]["payload"])
    assert outcome_from(403, "WAF: request blocked") == (True, False)
    assert outcome_from(200, "{}") == (False, True)
    sc = scorecard(events)
    assert sc["T1190"]["missed"] >= 1 and sc["T1190"]["blocked"] >= 1
    assert sc["T1071"]["detection_gap"] and sc["T1213"]["detection_gap"]
    print("techniques.py ok\n" + render(sc))


if __name__ == "__main__":
    demo()
