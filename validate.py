"""Finding validator — gate weak / false-positive findings before they are reported, and label
severity. Adapted from standard bug-bounty triage discipline (exploitability, scope, TANGIBLE
impact, dedup awareness, and a 'never-submit' list) — the idea pulled from public agentic-bug-
hunter tooling, reimplemented for our finding format. Directly fixes our measured false-positive
modes (decoy flags, unverified assertions) and stops noise class findings from reaching a report.

CLI: ./.venv/bin/python validate.py <findings.md> [scope.json]
"""
from __future__ import annotations

import re
import sys

from flag import DEFAULT_FLAG_RE, _is_placeholder

# Classes that are auto-disqualified STANDALONE — valid only as part of an exploit chain
# (a defender's/triager's "never submit" list; keep it about the class, not the wording).
NEVER_SUBMIT = [
    "missing security header", "content-security-policy", "hsts", "x-frame-options",
    "spf", "dkim", "dmarc", "graphql introspection", "version disclosure", "banner grab",
    "clickjacking", "self-xss", "open redirect", "cors wildcard", "tab nabbing", "tabnabbing",
    "rate limit", "logout csrf", "session persistence", "concurrent session", "weak tls",
    "weak cipher", "httponly", "secure flag", "autocomplete", "csv injection", "broken link",
    "host header injection", "verbose error", "directory listing",
]

# tangible impact — the server actually did something an attacker "walks away with"
_IMPACT = re.compile(
    r"flag\{|picoctf\{|\brows?\b.*return|return.*\brows?\b|\bdumped?\b|password|secret|"
    r"api[_-]?key|\btoken\b|accesskeyid|/etc/passwd|root:[^:]*:0:0|uid=\d+|is_admin|role=admin|"
    r"cross-(tenant|account)|(another|other) (user|tenant|org|account)('?s)?|social security|"
    r"\bssn\b|\bpii\b|metadata|credential|\brce\b|reverse shell|"
    r"command output|exfiltrat|"
    # XSS-execution class: browser-confirmed script execution IS the impact (no data token to match).
    # self-XSS still rejects via the never-submit gate, not this one.
    r"executed in the (post-?js )?dom|xss (confirmed|executed|fired)|payload (executed|fired)|"
    r"marker \S+ (executed|present|fired)|session (theft|hijack|cookie)|runs in a ?(victim|another)|"
    r"\bdom[- ]?xss\b|arbitrary javascript|execution (?:was )?(?:verified|confirmed)|"
    r"verified in a (?:real )?(?:headless )?browser|fired in the (?:post-?js )?dom", re.I)
# a concrete PoC needs BOTH a request and an observed response, not a bare assertion
_HAS_REQUEST = re.compile(r"\bcurl\b|\bGET \/|\bPOST \/|\bPUT \/|\bDELETE \/|https?://\S+", re.I)
# a response is an HTTP reply OR browser-render proof (browser_verify's DOM is the "response" for the
# stored/DOM-XSS class curl can't show).
_HAS_RESPONSE = re.compile(r"HTTP/\d|status[\s:=]+\d{3}|\b[1-5]\d\d\b|\{[^}]*[:,][^}]*\}|"
                           r"post-?js dom|executed in the (post-?js )?dom|browser[_ ]verif|"
                           r"rendered (dom|as (markup|live))", re.S | re.I)
_CHAINED = re.compile(r"\bchain(ed|s)?\b|-->|→|\bthen (use|forge|pivot|reach)\b|"
                      r"\bcombined with\b|\bleads? to\b|\bescalat", re.I)
# A section documenting a BLOCKED attack (or self-declaring no vuln) names the impact class it
# TRIED — so it trips _HAS_REQUEST/_HAS_RESPONSE/_IMPACT and gets stamped VALIDATED unless we
# catch the negative outcome. High-precision phrases only (real positive findings don't say
# "correctly rejected" / "no leak" / "centrally enforced"). Ceiling: a table-only negative with
# no prose won't match — ponytail: add a success-vs-fail response parser if false negatives recur.
_NEGATIVE = re.compile(
    r"no (confirmed |exploitable |valid )?vulnerabilit|nothing to (report|disclose)|"
    r"not (a|an) (real |security |confirmed )?finding|no (valid |confirmed )?findings?\b|"
    r"not (exploitable|injectable|vulnerable|abusable|bypassable)|\bhardened\b|\bimpossible\b|"
    r"correct(ly)?\W+(rejection|reject|block|gat|enforc|scoped)|"
    r"(properly|correctly|centrally) enforced|no (data |sensitive )?leak\b|"
    r"no (ssti|sqli|idor|bola|rce|injection|escalation|bypass|widening|share-based)\b|"
    r"tenant[- ]scoped|access[- ]control.{0,20}working|(attempts?|escalation).{0,25}failed|"
    r"no cross-(account|tenant|user) (data|reach)|"
    # impact word buried inside a DENIAL (hardened surface written in neutral prose, no other tell)
    r"only the caller|caller'?s own|own (records?|invoices?|data|account)\b|"
    r"never (comes? back|hands? back|returns?|exposes?|leaks?)|empty for any|"
    r"is not the caller|(resolved|scoped) (against|to) the (session|caller)", re.I)
# Robust backstop (the phrase list above kept missing new phrasings — "not demonstrated", "no
# impact proven", "banked lead"...). A real finding always shows the attacker OBTAINING something;
# a section that describes a BLOCKED outcome and shows no such success is not a finding, whatever
# impact-class keywords it names. So: reject when _BLOCKED matches and _SUCCESS does not.
_BLOCKED = re.compile(
    r"\b(blocked|denied|forbidden|rejected|invalid|filtered|"
    r"not demonstrated|no impact|banked lead|not exploitable|not injectable|"
    r"held\b|hardened|\b40[134]\b|"
    r"no (scope escape|arbitrary read|code execution|sandbox|leak|bypass|path[- ]prefix))", re.I)
_SUCCESS = re.compile(
    r"returned (another|other|the full|all |every )|leak(ed|s)\b|dump(ed|s)?\b|exfiltrat|"
    r"obtained|was able to|successfully (read|access|extract|forg|inject|auth)|disclos(ed|ure of)|"
    r"crack(ed)?\b|log(ged)? in as|took over|arbitrary (read|file|write)|"
    # achieved authentication/session takeover — "authenticated as carlos", "a valid authenticated
    # session", "session cookie for X" (NOT the theorized-takeover NOUN, which stays out of _SUCCESS
    # so "leads to account takeover" is still gated). Fixes the auth/brute-force false-negative where
    # an Expected:403-vs-Actual:302 repro tripped _BLOCKED with no recognized success verb.
    r"authenticated as|authenticated session|session (cookie|token) for |"
    # browser-verified client-side execution IS the achieved success for the XSS/DOM class (all
    # achieved phrasings — you don't "could verify in a browser", so no theorized-loophole). Fixes a
    # browser_verify-confirmed DOM XSS being gated because the section also named what the CSP blocked.
    r"execution (?:was )?(?:verified|confirmed)|verified in a (?:real )?(?:headless )?browser|"
    r"browser-(?:verified|confirmed)|\bxss (?:confirmed|verified|executed|fired)\b|"
    r"payload (?:executed|fired)|executed in the (?:post-?js )?dom|"
    # the browser_verify tell: the marker landed in the rendered DOM / the script ran (achieved)
    r"post-?js dom contained|dom contained \S+\s*=|"
    r"(?:injected |attacker[- ])?(?:script|js|javascript) (?:executes|ran)\b|"
    r"executed|command output|read another|accessed another|"
    # achieved cross-boundary read (require an achieved verb so "cross-tenant read correctly
    # rejected" does NOT match — only "read/retrieved (any/every) other tenant's ...")
    r"read (any |every |the )?other (tenant|user|account|org)|"
    r"retriev(e|ed)\b(?!.{0,20}(reject|block|denied|forbidden))|"
    r"returned .{0,40}(document|credential|secret|api[_-]?key)", re.I)
# Impact stated only as a POSSIBILITY, not a demonstration — "leads to / enables / an attacker could
# ... takeover", "potentially", "suggesting". The pipeline's discipline is report+PROVE, so a section
# whose only impact is theorized (and which shows no achieved _SUCCESS / real flag) is not a finding.
# Deliberately excludes "can" — "any account CAN read other users' PII" is a demonstrated read
# generalized, not a hypothetical (and it carries an achieved success anyway).
_THEORIZED = re.compile(
    r"\b(could|would|may|might)\s+(be\s+)?(allow|submit|change|lead|steal|read|access|expos|"
    r"leak|forg|exfiltrat|take\s*over|hijack|escalat|impersonat)|"
    r"\ban attacker('?s)?\s+(page\s+|site\s+|could\s+|would\s+|can\s+|might\s+)|"
    r"\bleads?\s+to\b|\benables?\b|\bpotential(ly)?\b|\bsuggest(s|ing)?\b|worth\s+(deeper|further)",
    re.I)


def _has_real_flag(t: str) -> bool:
    """A recovered, non-placeholder flag is decisive proof of a successful exploit — it overrides the
    negative/blocked gate (a section can describe a real capture AND note hardened sibling surfaces)."""
    return any(not _is_placeholder(m.group(0)) for m in DEFAULT_FLAG_RE.finditer(t or ""))


def never_submit_hit(text: str) -> str:
    low = (text or "").lower()
    return next((c for c in NEVER_SUBMIT if c in low), "")


def validate_finding(text: str) -> dict:
    """Gate ONE finding's text. Returns {ok, reasons:[(code,msg)], severity}."""
    t = text or ""
    reasons: list[tuple[str, str]] = []

    for m in DEFAULT_FLAG_RE.finditer(t):                 # decoy / placeholder evidence
        if _is_placeholder(m.group(0)):
            reasons.append(("decoy", f"evidence is a self-labeled decoy/placeholder: {m.group(0)}"))
            break
    if not (_HAS_REQUEST.search(t) and _HAS_RESPONSE.search(t)):
        reasons.append(("no-poc", "no concrete request+response PoC — reads as an assertion, "
                                  "not a reproduction"))
    if not _IMPACT.search(t):
        reasons.append(("no-impact", "no tangible impact shown (data/creds/RCE/cross-tenant) — "
                                     "theoretical or HTTP-200-only"))
    ns = never_submit_hit(t)
    # a concrete success (logged-in-as / exfil / code-exec / recovered flag) means this is NOT a
    # standalone-weak finding — the never-submit keyword is incidental evidence (e.g. 'HttpOnly' in a
    # captured Set-Cookie header on a critical SQLi auth-bypass). Only gate when there's no such win.
    if ns and not _CHAINED.search(t) and not (_SUCCESS.search(t) or _has_real_flag(t)):
        reasons.append(("never-submit", f"'{ns}' is a standalone never-submit class — needs a "
                                        f"chain to warrant a report"))
    # A blocked/hardened/self-negative section is only a non-finding when it shows NO countervailing
    # success. A concrete success (achieved-exfil phrasing or a recovered real flag) in the same
    # section overrides it — a legit finding often documents the hardened sibling surfaces it also
    # probed (was rejecting real cross-tenant BOLA reports whose section noted the blocked list route).
    if (_NEGATIVE.search(t) or _BLOCKED.search(t)) and not (_SUCCESS.search(t) or _has_real_flag(t)):
        reasons.append(("negative-result", "documents a blocked/hardened surface or self-declares "
                                            "no vulnerability — names the impact class it TRIED, "
                                            "not one it achieved (no success signal); not a finding"))
    # Impact stated only as a possibility ("leads to / an attacker could ... takeover") with no
    # achieved success is theorized, not demonstrated — report+PROVE means we don't submit it.
    if _THEORIZED.search(t) and not (_SUCCESS.search(t) or _has_real_flag(t)):
        reasons.append(("theorized", "impact is only theorized ('could/leads to/enables ...'), not "
                                     "demonstrated — no achieved success in the section; not a finding"))

    ok = not reasons
    return {"ok": ok, "reasons": reasons, "severity": _severity(t)}


_SEV = [  # (pattern, label) — first match wins, most severe first
    (r"auth(entication|z)? bypass.*admin|alg.?none|admin takeover|\brce\b|remote code|"
     r"metadata.*credential|ssrf.*metadata", "Critical"),
    (r"sql injection|sqli|full (db|database) (dump|read)|stored xss.*cookie|cross-tenant|"
     r"idor.*(write|delete)|mass assignment.*admin", "High"),
    (r"idor|bola|ssrf|xss|csrf.*sensitive|business logic", "Medium"),
]


def _severity(text: str) -> str:
    low = (text or "").lower()
    for pat, label in _SEV:
        if re.search(pat, low):
            return label
    return "Low"


def validate_report(md: str) -> tuple[str, dict]:
    """Split a findings.md into per-finding sections (## / ### headers), gate each, and return
    an annotated report + a summary. Weak findings are kept but flagged REJECTED with the reason."""
    parts = re.split(r'(?m)^(#{2,3}\s+.*)$', md or "")
    # parts = [preamble, header1, body1, header2, body2, ...]
    out, valid, rejected = [parts[0]] if parts else [], 0, 0
    for i in range(1, len(parts), 2):
        header = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        v = validate_finding(header + body)
        if v["ok"]:
            valid += 1
            out.append(f"{header}\n> ✅ VALIDATED · severity {v['severity']}\n{body}")
        else:
            rejected += 1
            why = "; ".join(m for _, m in v["reasons"])
            out.append(f"{header}\n> ❌ REJECTED · {why}\n{body}")
    summary = {"findings": (len(parts) - 1) // 2, "validated": valid, "rejected": rejected}
    banner = (f"# Validation summary\n\n{summary['validated']} validated · "
              f"{summary['rejected']} rejected of {summary['findings']} finding(s). "
              "Rejected = weak/unverified/never-submit; kept inline, flagged, for review.\n\n")
    return banner + "\n".join(out), summary


def demo() -> None:
    real = ("## IDOR: cross-tenant document read\n"
            "`curl -H 'Authorization: Bearer x' http://t/api/orgs/globex/documents/3002`\n"
            "HTTP/1.1 200 — returned another tenant's credential document: "
            "{\"value\":\"flag{cross_tenant}\"}\n")
    weak = ("## Missing HSTS header\nThe response is missing the Strict-Transport-Security "
            "header, which could potentially allow downgrade attacks.\n")
    decoy = ("## SQLi\n`curl http://t/api?q=1`\nHTTP/1.1 200 found flag{your_flag_here}\n")
    # a hardened-surface section: has request + 403 response + impact keyword — WITHOUT the
    # negative-outcome guard this validates as a phantom High (a real live-program FP, 2026-09-21)
    negative = ("## Surfaces tested → all controlled\n"
                "`GET http://t/api/orgs/globex/documents/3002` -> HTTP/1.1 403 — cross-tenant read "
                "correctly rejected; lookups tenant-scoped, no leak.\n")
    assert validate_finding(real)["ok"] and validate_finding(real)["severity"] == "High"
    assert not validate_finding(weak)["ok"]      # never-submit + no PoC + no impact
    assert not validate_finding(decoy)["ok"]     # placeholder/decoy evidence
    # negatives phrased as "hardened / not exploitable / no IDOR / attempts failed" (the section
    # that slipped the first guard on a deep live run) must also be gated
    hardened = ("### Cross-account authz — **hardened**\n"
                "`GET http://t/api/users/999` as B -> 403 folder-admin-permission-required; "
                "privilege-escalation attempts failed. No IDOR, no share-based widening.\n")
    assert not validate_finding(negative)["ok"]  # blocked outcome, not a finding
    assert not validate_finding(hardened)["ok"]  # "hardened"/"no IDOR"/"attempts failed"
    assert any(c == "negative-result" for c, _ in validate_finding(hardened)["reasons"])
    # blocked SSRF that NAMES metadata but shows no success (the 3rd phantom phrasing: "invalid",
    # "not demonstrated", "banked lead") — caught by the _BLOCKED-without-_SUCCESS backstop
    blocked_ssrf = ("### SSRF — POST /api/webhook_tests\n"
                    "`curl -d url=http://169.254.169.254/` -> HTTP 200 'Webhook URL is invalid'; "
                    "the cloud metadata IP and every encoding (hex 0xA9FEA9FE) returned invalid. "
                    "Redirect bypass not demonstrated. Banked lead — no impact proven.\n")
    assert not validate_finding(blocked_ssrf)["ok"]
    assert any(c == "negative-result" for c, _ in validate_finding(blocked_ssrf)["reasons"])
    assert any(c == "never-submit" for c, _ in validate_finding(weak)["reasons"])
    assert any(c == "negative-result" for c, _ in validate_finding(negative)["reasons"])
    _, s = validate_report(real + "\n" + weak)
    assert s == {"findings": 2, "validated": 1, "rejected": 1}, s
    _, sneg = validate_report(negative + "\n## Executive Summary\nNo confirmed vulnerabilities.\n")
    assert sneg["validated"] == 0, sneg          # a negative report yields ZERO phantom findings
    # a REAL finding whose section ALSO documents the hardened sibling surface it probed + a scope
    # note must still validate — a success (recovered flag / achieved read) overrides the negative
    # gate (the harbor BOLA false-negative, 2026-09-22: rejected because the section noted the
    # correctly-403 list route and a "not vulnerable" scope note).
    mixed = ("### Cross-tenant BOLA in GET /api/orgs/{org}/documents/{id}\n"
             "`curl -b cj.txt http://t/api/orgs/globex/documents/3002` -> HTTP 200 returned globex's "
             "document incl. its secret credential value flag{h4rb0r_cr0ss_t3n4nt_b0l4}. The list "
             "route `/api/orgs/globex/documents` correctly blocks with 403 (membership enforced); "
             "search is tenant-scoped. Scope note (checked, not vulnerable): unauthenticated access "
             "is rejected 401.\n")
    assert validate_finding(mixed)["ok"], validate_finding(mixed)["reasons"]
    _, smix = validate_report(mixed)
    assert smix["validated"] == 1, smix
    # guard the override isn't a loophole: the same negative WITHOUT a success stays rejected
    assert not validate_finding(mixed.split("-> HTTP 200")[0] +
            "-> HTTP 403 forbidden; list route correctly blocks; not vulnerable.\n")["ok"]
    # theorized-impact gate (adversarial FP set): "leads to ... takeover" with nothing obtained is
    # not a finding; but a real proven chain that ALSO says "leads to" is spared by the success.
    theorized = ("### Open redirect -> token theft\n`curl -i http://t/login?next=https://evil` -> "
                 "HTTP 302 Location: https://evil. Chained with OAuth this leads to full account "
                 "takeover.\n")
    assert not validate_finding(theorized)["ok"]
    assert any(c == "theorized" for c, _ in validate_finding(theorized)["reasons"])
    proven_chain = ("### SSRF -> metadata creds\n`curl http://t/fetch?url=http://169.254.169.254/"
                    "latest/meta-data/iam/` -> HTTP 200 returned the IAM AccessKeyId and "
                    "SecretAccessKey; this leads to full account takeover of the instance role.\n")
    assert validate_finding(proven_chain)["ok"], validate_finding(proven_chain)["reasons"]
    # off-vocab real bug (adversarial FN): terse cross-ACCOUNT PII read must validate
    ssn = ("### BOLA in GET /api/u/{id}/ssn\n`curl -b u1.txt http://t/api/u/2/ssn` -> HTTP 200 "
           "{\"ssn\":\"078-05-1120\"} — that is another account's social security number.\n")
    assert validate_finding(ssn)["ok"], validate_finding(ssn)["reasons"]
    print("validate.py ok")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] not in ("demo", "-t"):
        annotated, summary = validate_report(open(sys.argv[1]).read())
        print(annotated)
        sys.stderr.write(f"\n[validate] {summary}\n")
    else:
        demo()
