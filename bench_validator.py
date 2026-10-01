"""Validator precision/recall harness ("Hallucinbot") — measures the ONE thing the whole
"N validated findings" headline rests on: does the validator accept real findings and reject slop?

Scores validate.validate_report over a labeled corpus:
  POSITIVE = a real, reproduced finding — MUST graduate >=1 validated finding (miss = false NEGATIVE)
  NEGATIVE = slop / hardened / self-declared-no-vuln — MUST graduate 0 (accept = false POSITIVE)

Programs are pausing bounties over AI slop, so a false positive is the expensive error; but the
harbor benchmark proved false NEGATIVES are just as real (a correct report silently dropped). This
tracks both as precision/recall so a validator change can't regress either direction unseen.

Run: ./.venv/bin/python bench_validator.py        # scores + exits non-zero if any item misclassifies
"""
from __future__ import annotations

import sys

from validate import validate_report

# --- POSITIVES: real-shaped, reproduced findings across the classes we claim. Each has a concrete
# request+response PoC and tangible impact; several deliberately ALSO note a hardened sibling surface
# (the exact shape that caused the harbor false-negative) so that regression stays caught. ---
POSITIVES = [
    ("bola-cross-tenant",
     "### Cross-tenant BOLA in GET /api/orgs/{org}/documents/{id}\n"
     "`curl -b cj.txt http://t/api/orgs/globex/documents/3002` -> HTTP 200 returned globex's document "
     "including its secret credential value flag{h4rb0r_cr0ss_t3n4nt_b0l4}. The list route "
     "`/api/orgs/globex/documents` correctly blocks with 403 (membership enforced). Scope note "
     "(checked, not vulnerable): unauthenticated access is rejected 401.\n"),
    ("ssrf-metadata",
     "### SSRF -> cloud metadata credential theft\n"
     "`curl 'http://t/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/svc'`"
     " -> HTTP 200 returned the IAM role's AccessKeyId and SecretAccessKey. I obtained live AWS "
     "credentials for the instance role; the SSRF filter blocks localhost but not link-local.\n"),
    ("jwt-forge-admin",
     "### Auth bypass via alg:none JWT forgery\n"
     "`curl -H 'Authorization: Bearer <forged alg:none {\"role\":\"admin\"}>' http://t/api/admin/users`"
     " -> HTTP 200 returned the full admin user list. I successfully forged an admin token; the server "
     "accepts alg:none and does not verify the signature.\n"),
    ("sqli-dump",
     "### Union SQL injection in /search?q=\n"
     "`curl 'http://t/search?q=x%27+UNION+SELECT+username,password+FROM+users--'` -> HTTP 200 dumped "
     "every user's password hash. Extracted the full users table (rows returned inline).\n"),
    ("sqli-auth-bypass-with-cookie-evidence",
     "### SQL injection auth bypass in POST /login\n"
     "`curl -d \"username=administrator'--&password=x\" http://t/login` -> HTTP 302 to "
     "/my-account?id=administrator; I logged in as administrator with no password. Response evidence "
     "included the session cookie: `Set-Cookie: session=abc; Secure; HttpOnly; SameSite=None`. Full "
     "authentication bypass / account takeover.\n"),
    ("auth-bypass-brute-force-expected-vs-actual",
     "### Brute-force protection bypass via array-valued password in POST /login\n"
     "`curl -d '{\"username\":\"carlos\",\"password\":[\"123456\",...100 candidates...]}' http://t/login`"
     " tested every candidate in ONE request with no throttling. Expected: 403 / lockout after N "
     "failed attempts. Actual: HTTP 302 Location /my-account?id=carlos with a valid authenticated "
     "session for carlos — I authenticated as carlos, full account takeover from one request.\n"),
    ("dom-xss-browser-verified-with-blocked-context",
     "### DOM XSS via client-side prototype pollution (browser-confirmed)\n"
     "`GET /?__proto__[transport_url]=data:,alert(document.domain)//` — deparam.js writes the key onto "
     "Object.prototype and searchLogger.js reads the polluted `transport_url` as a dynamically injected "
     "script `src`. The inline-script path is blocked by CSP, but the injected-src path is not: "
     "execution was verified in a real headless browser (the marker fired in the post-JS DOM). Any "
     "victim opening the crafted link runs attacker JavaScript in this origin.\n"),
    ("stored-xss",
     "### Stored XSS in profile bio (browser-confirmed)\n"
     "`curl -X POST http://t/api/profile -d 'bio=<img src=x onerror=document.title=`XSSMARK`>'` then "
     "browser_verify of /u/alice showed the marker XSSMARK executed in the post-JS DOM. Confirmed "
     "execution (not escaped); an attacker's script runs in a victim's authenticated session.\n"),
]

# --- NEGATIVES: the slop/hardened/no-vuln shapes a strict validator must reject. Mix of the
# measured false-positive phrasings (live-program phantoms) + standalone never-submit classes. ---
NEGATIVES = [
    ("missing-header",
     "### Missing HSTS header\nThe response lacks Strict-Transport-Security, which could allow a "
     "downgrade attack. Recommend adding the header.\n"),
    ("decoy-flag",
     "### SQLi\n`curl http://t/api?q=1` -> HTTP 200 found flag{your_flag_here}. Looks exploitable.\n"),
    ("hardened-authz",
     "### Cross-account authz — hardened\n`GET http://t/api/users/999` as B -> 403 "
     "folder-admin-permission-required; privilege-escalation attempts failed. No IDOR, no widening.\n"),
    ("blocked-ssrf",
     "### SSRF — POST /api/webhook_tests\n`curl -d url=http://169.254.169.254/` -> HTTP 200 "
     "'Webhook URL is invalid'; the cloud metadata IP and every encoding (hex 0xA9FEA9FE) returned "
     "invalid. Redirect bypass not demonstrated. Banked lead — no impact proven.\n"),
    ("graphql-introspection",
     "### GraphQL introspection enabled\n`curl -d '{\"query\":\"{__schema{types{name}}}\"}' "
     "http://t/graphql` -> HTTP 200 returned the schema. Introspection is on.\n"),
    ("self-xss",
     "### Self-XSS in the dev console\nPasting `<img src=x onerror=alert(1)>` into the JS console "
     "runs it. Users could be socially engineered into doing this.\n"),
    ("open-redirect-alone",
     "### Open redirect on /login?next=\n`curl -i 'http://t/login?next=https://evil.com'` -> HTTP 302 "
     "Location: https://evil.com. The next param is not validated.\n"),
    ("negative-summary",
     "### Assessment result\nProbed IDOR, SSRF, and SQLi across the API. All surfaces are correctly "
     "enforced and tenant-scoped; no confirmed vulnerabilities.\n"),
]


def score():
    tp = fn = tn = fp = 0
    misses = []
    for name, text in POSITIVES:
        _, s = validate_report(text)
        if s["validated"] >= 1:
            tp += 1
        else:
            fn += 1
            misses.append(f"  FALSE NEGATIVE: positive '{name}' graduated 0 (should be >=1)")
    for name, text in NEGATIVES:
        _, s = validate_report(text)
        if s["validated"] == 0:
            tn += 1
        else:
            fp += 1
            misses.append(f"  FALSE POSITIVE: negative '{name}' graduated {s['validated']} (should be 0)")
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    return {"tp": tp, "fn": fn, "tn": tn, "fp": fp, "precision": round(prec, 3),
            "recall": round(rec, 3)}, misses


def main():
    r, misses = score()
    print("==== VALIDATOR PRECISION/RECALL ====")
    print(f"  positives: {r['tp']}/{r['tp']+r['fn']} accepted (recall {r['recall']})   "
          f"— false negatives {r['fn']}")
    print(f"  negatives: {r['tn']}/{r['tn']+r['fp']} rejected (precision {r['precision']})  "
          f"— false positives {r['fp']}")
    for m in misses:
        print(m)
    print("====================================")
    return 0 if not misses else 1


def demo() -> None:
    r, misses = score()
    assert not misses, misses                 # the corpus itself is the check: 0 misclassifications
    assert r["precision"] == 1.0 and r["recall"] == 1.0, r
    print("bench_validator.py ok")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("demo", "-t"):
        demo()
    else:
        sys.exit(main())
