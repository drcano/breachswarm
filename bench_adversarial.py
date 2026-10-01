"""Adversarial external-validity probe for the finding validator (the held-out companion to
bench_validator.py). bench_validator's 1.0/1.0 is measured on a corpus co-authored with validate.py's
regexes — the teach-to-the-test risk. This set is DIFFERENT: every item is phrased the way a real
triager or a real LLM slop report reads, deliberately aimed NEAR the regex decision boundary
(impact words buried inside a denial, a never-submit class dressed with a chain phrase, a
hallucinated "this dumps everything" over a 404 response, a real bug written with an off-vocabulary
success verb). None was reverse-engineered to pass.

It is a MEASUREMENT, not a gate: misclassifications are the point (they map where the regex validator
breaks on independent data), so it prints a confusion matrix and every miss and exits 0. The expensive
error for a real program is a FALSE POSITIVE (slop stamped VALIDATED → the program pauses the bounty);
false negatives (a real bug silently dropped) matter too — harbor proved that — so both are tracked.

Ground-truth labels are a competent triager's call under this pipeline's own "report + PROVE, don't
theorize" discipline: NEGATIVE = nothing was actually obtained (blocked, reflection-only, or impact
merely theorized), POSITIVE = the attacker demonstrably walked away with something.

Run: ./.venv/bin/python bench_adversarial.py
"""
from __future__ import annotations

from validate import validate_finding

# NEGATIVE = a strict triager reports NOTHING here. Each is built to slip a specific regex guard.
# (label, why-it's-really-a-non-finding, text)
NEGATIVES = [
    ("halluc-404-dump",
     "LLM slop: claims a full dump but the response it pastes is a 404 (no data returned)",
     "### SQL injection in GET /api/search\n"
     "`curl 'http://t/api/search?q=1%20UNION%20SELECT%20password%20FROM%20users'` -> HTTP 404 Not "
     "Found. This dumps every user's password from the database and confirms full SQL injection.\n"),

    ("neutral-hardened-idor",
     "access control actually HOLDS; phrased in neutral prose with none of the negative keywords",
     "### Object access on GET /api/invoices/{id}\n"
     "`curl -b b.txt http://t/api/invoices/1002` as user B -> HTTP 200 returned user B's own invoice. "
     "Incrementing the id to 1003, 1004 keeps returning only the caller's own records; the id is "
     "resolved against the session owner, so another account's invoice never comes back.\n"),

    ("impact-word-in-denial",
     "names credential/token/secret but every one is inside a statement that access was denied",
     "### Credential exposure check on GET /api/users/{id}/keys\n"
     "`curl http://t/api/users/7/keys` as user 3 -> HTTP 200 `{\"keys\":[]}`. The endpoint never "
     "hands back another user's api_key, token, or secret; the credential list is empty for any id "
     "that is not the caller.\n"),

    ("reflection-not-execution",
     "input reflected in HTML is not XSS without proof of execution — reflection only",
     "### Reflected XSS in /search?q=\n"
     "`curl 'http://t/search?q=<b>hi</b>'` -> HTTP 200; the q parameter is reflected verbatim inside "
     "the results heading in the HTML response. Marking as reflected XSS.\n"),

    ("openredirect-theorized-token",
     "open redirect (never-submit) with only a THEORIZED token-theft chain — nothing obtained",
     "### Open redirect to OAuth token theft in /login?returnUrl=\n"
     "`curl -i 'http://t/login?returnUrl=https://evil.example'` -> HTTP 302 Location: "
     "https://evil.example. Chained with the OAuth flow this leads to the access token being "
     "delivered to an attacker-controlled origin and full account takeover.\n"),

    ("ratelimit-theorized-ato",
     "no-rate-limit (never-submit) with a theorized 'credential stuffing -> takeover'; none performed",
     "### Missing rate limit on POST /login enables account takeover\n"
     "`curl -d 'user=a&pass=b' http://t/login` -> HTTP 200 repeated 500x with no throttling or "
     "lockout. This enables credential stuffing which leads to account takeover of any user with a "
     "weak password.\n"),

    ("cors-reflect-no-creds",
     "Origin reflection without credentialed access is not exploitable; dodges the 'cors wildcard' word",
     "### CORS misconfiguration on /api/me\n"
     "`curl -H 'Origin: https://evil.example' http://t/api/me` -> HTTP 200 with "
     "Access-Control-Allow-Origin: https://evil.example reflected back. Cross-origin reads of the "
     "profile are possible.\n"),

    ("verbose-stack-secret-word",
     "a stack trace (never-submit: verbose error) that happens to contain the word secret; nothing read",
     "### Verbose error discloses internals on /api/order\n"
     "`curl -d '{}' http://t/api/order` -> HTTP 500 with a Python traceback naming "
     "settings.SECRET_KEY_PATH and the file /app/order.py line 42. Information disclosure of the "
     "application internals.\n"),

    ("speculative-blind-timing",
     "40ms timing wobble is speculative ('suggesting possible'), no confirmed oracle or extraction",
     "### Possible blind SQL injection in /filter?cat=\n"
     "`curl 'http://t/filter?cat=1;SELECT%20pg_sleep(1)--'` -> HTTP 200; response time varied by "
     "~40ms versus baseline, suggesting a possible time-based blind SQL injection worth deeper "
     "testing.\n"),

    ("csrf-theorized-pwchange",
     "plain CSRF with only a theorized password change; no cross-origin success demonstrated",
     "### CSRF on POST /account/change-password\n"
     "`curl -b b.txt -d 'new=Pwn123!' http://t/account/change-password` -> HTTP 200 password "
     "updated. The form carries no anti-CSRF token, so an attacker page could submit this on the "
     "victim's behalf and change their password.\n"),

    ("negative-json-blob",
     "a clean/no-vuln result delivered as a terse JSON status line, little prose to match on",
     "### Authorization sweep result\n"
     "`GET http://t/api/orgs/globex/documents/3002` as acme -> HTTP 403 "
     "`{\"error\":\"forbidden\",\"reason\":\"membership\"}`. Ran the id-transform matrix over 40 "
     "objects; every cross-org read returned 403.\n"),

    ("idor-same-user",
     "the 'other' id resolves to the SAME authenticated user — no boundary actually crossed",
     "### IDOR in GET /api/profile?uid=\n"
     "`curl -b alice.txt 'http://t/api/profile?uid=99999'` -> HTTP 200 returned a profile with "
     "email alice@t and her api_key. The uid parameter is attacker-controlled, so this is an IDOR "
     "exposing the api_key.\n"),
]

# POSITIVE = a real, PROVEN bug written with off-vocabulary phrasing (probing false NEGATIVES).
POSITIVES = [
    ("passwd-slang-verb",
     "real file read, success verb is slang not in the vocab, but /etc/passwd + root line are decisive",
     "### Path traversal in GET /download?file=\n"
     "`curl 'http://t/download?file=../../../../etc/passwd'` -> HTTP 200 and the server coughed up "
     "the whole file: root:x:0:0:root:/root:/bin/bash. Arbitrary file read on the host.\n"),

    ("idor-ssn-terse",
     "real cross-account read, terse, 'cross-account' (not the vocab's 'cross-tenant'), sensitive PII",
     "### Broken object-level auth in GET /api/u/{id}/ssn\n"
     "`curl -b user1.txt http://t/api/u/2/ssn` -> HTTP 200 `{\"ssn\":\"078-05-1120\"}` — that is "
     "user 2's social security number returned to user 1. Any account can read any other account's "
     "PII by changing the id.\n"),

    ("blind-boolean-proven",
     "a genuinely proven boolean oracle + extracted hash, phrased without 'dumped/leaked'",
     "### Blind SQL injection (boolean) in the tracking cookie\n"
     "`curl -b \"TrackingId=x' AND 1=1--\"` -> HTTP 200 welcome banner present; `TrackingId=x' AND "
     "1=2--` -> HTTP 200 banner absent. A reliable boolean oracle. Walked it character by character "
     "and recovered the administrator password hash 2a$10$k7f...9Qe.\n"),

    ("xxe-inline-proof",
     "real XXE, entity expansion shows the passwd contents inline (decisive tokens present)",
     "### XXE external entity in POST /product/stock\n"
     "`curl -d '<?xml version=\"1.0\"?><!DOCTYPE t [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
     "<stockCheck><productId>&x;</productId></stockCheck>' http://t/product/stock` -> HTTP 400 whose "
     "error body embedded the entity: daemon:x:1:1:daemon:/usr/sbin. Host file read confirmed.\n"),
]


def run():
    rows = []            # (kind, label, expected_ok, got_ok, why)
    for label, why, text in NEGATIVES:
        v = validate_finding(text)
        rows.append(("neg", label, False, v["ok"], why))
    for label, why, text in POSITIVES:
        v = validate_finding(text)
        rows.append(("pos", label, True, v["ok"], why))
    return rows


def main():
    rows = run()
    fp = [r for r in rows if r[0] == "neg" and r[3]]        # negative validated  -> false positive
    fn = [r for r in rows if r[0] == "pos" and not r[3]]    # positive rejected   -> false negative
    n_neg = sum(1 for r in rows if r[0] == "neg")
    n_pos = sum(1 for r in rows if r[0] == "pos")
    print("==== ADVERSARIAL VALIDATOR PROBE (held-out) ====")
    print(f"  negatives: {n_neg - len(fp)}/{n_neg} correctly rejected  "
          f"— FALSE POSITIVES {len(fp)}  (the expensive error)")
    print(f"  positives: {n_pos - len(fn)}/{n_pos} correctly accepted  "
          f"— FALSE NEGATIVES {len(fn)}")
    if fp:
        print("\n  FALSE POSITIVES (slop the validator stamped VALIDATED):")
        for _, label, _, _, why in fp:
            print(f"    ✗ {label}: {why}")
    if fn:
        print("\n  FALSE NEGATIVES (real bugs the validator dropped):")
        for _, label, _, _, why in fn:
            print(f"    ✗ {label}: {why}")
    if not fp and not fn:
        print("\n  no misclassifications — validator held on the held-out set.")
    print("================================================")
    return rows


if __name__ == "__main__":
    main()
