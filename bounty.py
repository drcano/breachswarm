"""Authorized bug-bounty / security-research runner.

Refuses to run unless a scope file authorizes the target (scope.py). Then runs the
web specialist against the in-scope host, captures a full audit trail, generates a
findings report, and appends a row to the success-metrics ledger.

Usage:
  ./.venv/bin/python bounty.py --scope scope.json --target https://app.example.com
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
from collections import defaultdict
import subprocess
import time
import uuid
from pathlib import Path

from claude_agent_sdk import (query, ClaudeAgentOptions, tool,
                              create_sdk_mcp_server, AssistantMessage, TextBlock,
                              ResultMessage)
from sandbox import make_sandbox, IMAGE as SANDBOX_IMAGE
from scope import Scope
from config import MODEL
from specialists import SPECIALISTS
from writeup import save_audit
from report import generate_report

METRICS = "bounty_metrics.jsonl"

BOUNTY_SYS = SPECIALISTS["web"] + (
    "\n\nBUG-BOUNTY MODE. You are testing an AUTHORIZED, in-scope target only. "
    "Rules of engagement: stay strictly on the target host(s) named in the task — "
    "never pivot to any other host; respect the stated rate limit; perform NO "
    "destructive actions (no data deletion, no DoS, no account lockouts). Enumerate "
    "and safely confirm real vulnerabilities (OWASP classes). For each finding record: "
    "class, endpoint, a minimal proof-of-concept request, observed evidence, impact, "
    "and remediation.\n"
    "MAP THE FULL SURFACE BEFORE HUNTING: a validator has nothing to validate if you never reach the "
    "exploitable endpoint. FIRST run subdomain_recon (apex) + endpoint_recon + `crawl` (live param "
    "URLs) + `secret_scan` (verified leaked creds in the JS — highest single-bounty yield) + mine the "
    "JS/source-maps + ingest any API docs/Swagger, and build a model of endpoints, params, and roles. "
    "Discovery breadth — not cleverer exploits — is what separates finders from non-finders.\n"
    "VERIFIABLE BITES: decompose each objective and CONFIRM EVERY STEP before proceeding (endpoint "
    "exists -> object reference exists inside it -> access persists when logged-out/as another user -> "
    "impact). Do NOT hunt-then-validate-at-the-end — that is how you waste turns down hallucinated "
    "paths. Each step is a small deterministic check.\n"
    "DETAILED TECHNIQUE, NOT TYPICAL PAYLOADS: for a suspected class, write a SHORT script that tests "
    "MANY variants in one shot (encodings, boundary values, alternate content-types, header/host "
    "confusion) rather than the one obvious payload — generic attempts only find what a scanner "
    "already found and dup'd.\n"
    "ALWAYS GO FOR IMPACT — you are a BUG-BOUNTY HUNTER, not a pentester. Only pursue "
    "findings whose SECURITY IMPACT you can DEMONSTRATE on REAL data. Do NOT waste time or "
    "tokens on things no program pays for: missing security headers, CORS misconfig without "
    "credentialed exfil, self-XSS, open redirect alone, clickjacking, verbose errors, version "
    "disclosure without a working CVE, GraphQL introspection alone, rate-limits on non-critical "
    "endpoints, or 'theoretical / may-be-exploitable-later' issues — these are defense-in-depth "
    "noise; SKIP them. Rank by impact, high first: RCE > auth-bypass-to-admin / account takeover "
    "> SSRF to internal/metadata > MASS PII EXPOSURE (leaking other users' names/emails/phones "
    "is often an easy crit — go for it) > IDOR/BOLA write/delete > SQLi data read > stored XSS "
    "with session theft. A finding you cannot reproduce with a concrete request and observed "
    "impact is not a finding.\n"
    "RECON WIDE BEFORE DEEP: the niche, high-value scope hides in the JavaScript, not the UI. "
    "MINE the main site's JS bundles (and .map source maps) for hidden API endpoints, routes, "
    "params, and other in-scope assets before drilling into the obvious app. Run `subdomain_recon` "
    "FIRST on the apex domain — it enumerates subdomains from CT logs and flags EXPOSED-ORIGIN hosts "
    "(not behind the WAF/CDN) and staging/uat/legacy/admin names, the forgotten surface where bugs "
    "actually survive; press hard on what it banks. Run `endpoint_recon` "
    "EARLY: it enumerates endpoints and flags the weird/forgotten ones (legacy/admin/debug/internal/"
    "undocumented) — the surface a company left untouched, where the real bugs hide — and banks them "
    "as leads. PRESS HARD on those flagged endpoints; a normal-looking app often hides its bugs on "
    "the one odd route nobody maintains. If given a seed "
    "authenticated request (cookies/token/endpoint), reuse that exact auth for all testing.\n"
    "DESTRUCTIVE = FORBIDDEN, no exceptions: never delete/modify data, change a password/2FA/"
    "email, or lock an account — a real hunter's agent deleted an account overnight and lost the "
    "repro. When you gain CODE EXECUTION (SSTI/RCE/deserialization), PROVE it by READING a file or "
    "evaluating a harmless expression (7*7, `id`, cat a secret) — NEVER by invoking a delete/destroy/"
    "gdprDelete-style method, even if a destructive call is the target's 'intended' solution. "
    "If a test WOULD change state, do not run it (or revert immediately). When you cannot "
    "confirm impact without a second account you don't have, report it with the evidence you have "
    "rather than causing damage. CLEANUP EXCEPTION: when you finish, you MAY delete the test "
    "objects YOU created this run (folders, keys, bundles) — those DELETEs are permitted; deleting "
    "anything you did not create this run is not.\n"
    "STEALTH / LOW FOOTPRINT (a good authorized tester is a ninja, not a bull): keep "
    "the request count MINIMAL. Do NOT brute-force endpoint names with wordlists or "
    "`for` loops of dozens of guesses — enumerate from links/JS/known routes instead. "
    "Form a hypothesis and send the ONE right request rather than spraying payload "
    "variants. NEVER re-probe an endpoint that already returned errors (404/403/500) — "
    "it is a dead end or a tarpit; move on. One clean proof per finding is enough; "
    "stop as soon as a vuln is confirmed. Every wasted error request is noise a "
    "defender sees.\n"
    "EXPLOIT PRIMITIVES (one call runs the whole routine in-sandbox, respecting scope+rate): "
    "`ssrf_recon` maps internal surfaces through a confirmed SSRF param; `oob` confirms a BLIND "
    "bug (SSRF/XXE/redirect-to-internal/webhook) out-of-band — mint a callback URL, inject it, then "
    "check the token; a logged hit is proof where a timeout is not; `blind_extract` pulls a "
    "secret through a boolean-blind oracle; `time_blind` does the same via response delay; "
    "`jwt_forge` mints auth-bypass tokens; `authz_matrix` sweeps a request across auth contexts x "
    "resource ids to flag broken access control (IDOR/BOLA/auth-bypass — the highest-paid class); "
    "`browser_verify` renders a URL in a real headless browser to prove STORED/DOM XSS (plant a "
    "payload that writes a unique marker on execution, then check it renders) — the class curl "
    "can't see, and on a real program the EXECUTION PROOF is the deliverable (no victim to click); "
    "`exploit_server` drives the deliver-to-victim half for client-side labs (STORE a payload on the "
    "exploit server, DELIVER_TO_VICTIM, read the ACCESS LOG for the exfil) — for CSP-bypass / "
    "AngularJS-sandbox-escape / DOM-clobbering / prototype-pollution→XSS, craft the payload, prove it "
    "with browser_verify, then deliver via exploit_server; `browser_session` goes further — a REAL "
    "AUTHENTICATED browser (pass the session "
    "header/cookies/localStorage-JWT) that renders the post-login SPA and LOGS EVERY XHR/fetch the "
    "app fires, handing you the real authenticated API surface (the endpoints static crawls miss) — "
    "run it early on any JS-heavy/authenticated target; `note` records a confirmed fact to reuse; "
    "`crawl` actively crawls a live app into "
    "the PARAM-BEARING URLs an attacker can hit; `dast_scan` then ACTIVELY fuzzes those URLs "
    "(reflected XSS / error SQLi / LFI / SSTI / open-redirect / CRLF) to catch the injectable params "
    "a manual pass misses — the crawl->dast pipeline is the discovery->verify loop; treat dast hits "
    "as LEADS and prove impact. Prefer these "
    "over hand-looping requests once you've CONFIRMED the underlying primitive (the injectable "
    "param, the SSRF fetch, the JWT).\n"
    "ADVANCED CLASSES (money bugs a scanner misses — reach for the matching primitive): `race` for "
    "one-time/limited actions (coupon/gift-card reuse, balance overdraw, quota/rate bypass — TOCTOU "
    "under concurrency); `mass_assign` on any write to smuggle privileged fields (role/is_admin/"
    "verified/org_id) and confirm they stick; `graphql` to introspect + surface the attackable "
    "mutations/PII/node-id BOLA on a /graphql endpoint; `xxe` to mint XML-external-entity payloads "
    "(pair with `oob` for blind); `smuggle` to detect front/back-end request-smuggling desync "
    "(detection only); `protopollute` tests prototype pollution on JSON-merge/config sinks; "
    "`deserialize` fingerprints a serialized cookie/param blob and mints the right OOB probe (confirm "
    "blind deser with `oob`). On a checkout/redeem/withdraw/vote flow ALWAYS try `race`; on any "
    "object-update ALWAYS try `mass_assign`.\n"
    "BANK YOUR LEADS: the moment you notice something promising you can't fully chase now (out of "
    "turns, needs a 2nd account, needs another technique), call `lead` to record it — it persists "
    "per-target so the NEXT run resumes the hunt there instead of re-discovering it. Recon findings "
    "and confirmed facts already persist; leads are how an unfinished thread survives to next time.\n"
    "NEVER REPORT A PRIMITIVE ALONE — criticals are CHAINS, not single bugs. A lone SSRF/IDOR/"
    "open-redirect/XSS/secret is a LEAD until you chain it or prove real impact. Once you've confirmed "
    "2+ primitives, call `chain_scan`: it matches your banked primitives against canonical chain "
    "templates (SSRF->cloud-metadata->IAM takeover, open-redirect->OAuth->account-takeover, "
    "IDOR->admin->RCE, ...) and hands you the next hop. Pursue the READY chains to turn mediums into "
    "the criticals that actually pay."
)


def _server(sb, scope=None, id_header=""):
    """Stealth-aware sandbox tool: dead-end detector (from solver) + a per-endpoint
    circuit breaker that STOPS sending real traffic to endpoints that keep erroring
    (the 190-hit tarpit in the Fortress run). Tracks a request/error footprint."""
    from solver import (_stall_nudge, _is_unproductive, _decoy_nudge, _waf_nudge, _rate_nudge, repeat_guard,
                        _injection_guard, _blind_extract, _JWT_RE)
    from scratchpad import Scratchpad
    from primitives import jwt_forge, time_blind, ssrf_recon, authz_matrix
    from primitives import race, mass_assign, graphql as gql, xxe, smuggle
    from primitives import protopollute, deserialize
    stall = {"window": [], "cooldown": 0}
    sp = Scratchpad()   # shared confirmed-facts scratchpad, reused by the primitives below
    endpoint_errs = defaultdict(int)   # path -> consecutive error count
    fp = {"tool_calls": 0, "error_results": 0, "circuit_blocks": 0, "destructive_blocks": 0, "loop_blocks": 0}
    ERR_THRESH = 3
    from safety import guard_destructive, is_http_create, refs_in_response
    import os as _os
    _destructive_ok = _os.getenv("CTF_ALLOW_DESTRUCTIVE") == "1"
    created_refs = set()   # ids/paths this session CREATED — deletable for cleanup (safety.py)
    _oob_public = _os.getenv("OOB_PUBLIC_URL", "")            # tunnel URL the TARGET can reach
    _oob_local = _os.getenv("OOB_LOCAL_URL", "http://127.0.0.1:9000")  # where the runner polls
    if not _oob_public:                                       # auto-stand-up a collaborator if we can
        try:                                                 # (no-op when no cloudflared/ngrok on PATH)
            import oob as _oobmod
            _prov = _oobmod.provision(port=9000, timeout=25)
            _oob_public = _prov["public_url"]; _oob_local = _prov["local_base"]
            print(f"[oob] auto-provisioned collaborator: {_oob_public} (via {_prov['tool']})")
        except Exception as _e:
            print(f"[oob] no auto collaborator ({str(_e)[:80]}); blind-OOB confirmation unavailable "
                  f"unless OOB_PUBLIC_URL is set")

    def _paths(cmd):
        return re.findall(r'https?://[^/\s"\']+/([^\s"\'?]*)', cmd or "")

    @tool("sandbox_bash", "Run a shell command in the (network-enabled) sandbox",
          {"command": str})
    async def sandbox_bash(args):
        cmd = args.get("command", "")
        allowed, why = guard_destructive(cmd, _destructive_ok, created_refs)  # no-destruction rail
        if not allowed:
            fp["destructive_blocks"] += 1
            return {"content": [{"type": "text", "text": why}]}
        paths = _paths(cmd)
        tripped = sorted({p for p in paths if endpoint_errs[p] >= ERR_THRESH})
        if tripped:  # circuit open: refuse to send more real traffic to dead endpoints
            fp["circuit_blocks"] += 1
            return {"content": [{"type": "text", "text":
                    f"[stealth/circuit-open] endpoint(s) {tripped} already returned "
                    f"errors {ERR_THRESH}+ times — request NOT sent (footprint control). "
                    "These are dead ends/tarpits. Pivot to a different endpoint or "
                    "technique; do not keep probing them."}]}
        allow_rep, rep_msg = repeat_guard(cmd, stall)      # exact-repeat loop guard (saves footprint)
        if not allow_rep:
            fp["loop_blocks"] += 1
            return {"content": [{"type": "text", "text": rep_msg}]}
        out, inj = _injection_guard(sb.bash(cmd), stall)   # defang untrusted target output
        fp["tool_calls"] += 1
        if is_http_create(cmd):        # track self-created objects so cleanup DELETEs are allowed
            created_refs.update(refs_in_response(out))
        err = _is_unproductive(out)
        if err:
            fp["error_results"] += 1
        for p in paths:            # per-endpoint: count errors, reset on a clean hit
            endpoint_errs[p] = endpoint_errs[p] + 1 if err else 0
        return {"content": [{"type": "text", "text": out + _stall_nudge(out, stall)
                             + _decoy_nudge(out) + _waf_nudge(out, stall)
                             + _rate_nudge(out, stall) + rep_msg + inj}]}

    # --- executable exploit primitives (same routines solver exposes for CTF, now in bounty
    # mode). They issue requests THROUGH the enforced sandbox -> proxy, so scope + rate limit
    # still apply. They intentionally bypass the sandbox_bash circuit-breaker (they run their own
    # tight paced loops); all are read/local-only (no destructive verbs), so the no-destruct
    # rail is not weakened. ---
    @tool("note", "Record a CONFIRMED fact to the shared scratchpad so later steps reuse it "
          "instead of re-deriving (e.g. key='param' value='q'; key='admin_token' value='ey...').",
          {"key": str, "value": str})
    async def note(args):
        sp.note(args.get("key", ""), args.get("value", ""))
        return {"content": [{"type": "text", "text": "noted.\n" + sp.summary()}]}

    @tool("lead", "Record an INTERESTING but UNCONFIRMED exploit candidate to resume on a later "
          "run (persisted per-target, so a re-run continues the hunt instead of re-discovering). "
          "e.g. observation='POST /automations reflects {{7*7}} unescaped in name', why='possible "
          "SSTI, needs a deeper probe'. Use it whenever you notice something promising you can't "
          "fully chase now (out of turns, needs a 2nd account, needs a different technique).",
          {"observation": str, "why": str, "surface": str})
    async def lead(args):
        sp.add_lead(args.get("observation", ""), args.get("why", ""), args.get("surface", ""))
        return {"content": [{"type": "text", "text": "lead recorded.\n" + sp.summary()}]}

    @tool("jwt_forge", "Forge JWT auth-bypass tokens in ONE call: alg:none variants, weak-HS256 "
          "secret crack + re-sign, and RS256->HS256 alg-confusion, with your claim overrides. For "
          "alg-confusion give the RSA public key as `public_key` (PEM) OR just point the tool at the "
          "JWKS — `jwks_url` (e.g. https://target/jwks.json) or `jwks` (the JWK/JWKS JSON): it builds "
          "the PEM from the JWK itself and emits both trailing-newline variants, so you DON'T hand-roll "
          "JWKS->PEM->HS256. Use when the target authenticates with a JWT.",
          {"token": str, "claims": str, "wordlist": str, "public_key": str,
           "jwks": str, "jwks_url": str, "timeout": int})
    async def jwt_forge_tool(args):
        raw = args.get("claims") or "{}"
        try:
            claims = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except Exception:
            return {"content": [{"type": "text", "text": "jwt_forge error: 'claims' must be a JSON "
                    "object string, e.g. '{\"role\":\"admin\"}'."}]}
        res = jwt_forge.run(sb, {**args, "claims": claims})
        m = _JWT_RE.search(res)
        if m:
            sp.note("forged_jwt", m.group(0))
        return {"content": [{"type": "text", "text": res}]}

    @tool("blind_extract", "Extract a secret through a CONFIRMED boolean-blind oracle in ONE call: "
          "paced binary-search extraction in-sandbox, auto-escalates URL-encode depth past a WAF, "
          "backs off on 429. oracle_url must contain {cond}; true_marker is present ONLY on a true "
          "response; subquery is the secret expression. For an auth-gated endpoint pass auth as a "
          "JSON string in `headers`.",
          {"oracle_url": str, "true_marker": str, "subquery": str,
           "max_len": int, "encode_depth": int, "delay": float, "headers": str})
    async def blind_extract_tool(args):
        if isinstance(args.get("headers"), str) and args["headers"].strip():
            try:
                args = {**args, "headers": json.loads(args["headers"])}
            except Exception:
                pass
        return {"content": [{"type": "text", "text": _blind_extract(sb, args)}]}

    @tool("time_blind", "Time-based blind extraction in ONE call: binary-searches a secret using "
          "response DELAY as the oracle (slow==true), median-of-N against jitter, backs off on 429. "
          "Use when injection is blind with NO content marker. oracle_url must contain {cond}; "
          "sleep_expr is the DB sleep (sleep({d}) MySQL, pg_sleep({d}) Postgres).",
          {"oracle_url": str, "inject_template": str, "sleep_expr": str, "subquery": str,
           "delay_s": float, "threshold_s": float, "reps": int, "max_len": int,
           "encode_depth": int, "delay_between": float})
    async def time_blind_tool(args):
        return {"content": [{"type": "text", "text": time_blind.run(sb, args)}]}

    @tool("ssrf_recon", "Map internal surfaces THROUGH a confirmed SSRF/fetch param in ONE call: "
          "sweeps cloud metadata + common loopback services, reflects the fetched body, highlights "
          "creds/banners. Use after confirming a param makes the SERVER fetch a URL. ssrf_url must "
          "contain {target}.",
          {"ssrf_url": str, "targets": str, "success_re": str, "reflect_re": str,
           "timeout": float, "delay_between": float})
    async def ssrf_recon_tool(args):
        return {"content": [{"type": "text", "text": ssrf_recon.run(sb, args)}]}

    @tool("oob", "Confirm a BLIND vuln (SSRF/XXE/blind injection/webhook) OUT-OF-BAND when nothing "
          "comes back in-band. action='mint' returns a unique callback URL — inject it into the "
          "suspected sink (SSRF `url=`, an XXE SYSTEM entity, a webhook target, a redirect chain). "
          "action='check' with the returned token polls the collaborator; a logged hit PROVES the "
          "target's server reached out (a timeout/refused is NOT proof). Needs OOB_PUBLIC_URL set.",
          {"action": str, "token": str})
    async def oob_tool(args):
        import oob as _oobmod
        if not _oob_public:
            return {"content": [{"type": "text", "text": "[oob] no collaborator configured "
                    "(set OOB_PUBLIC_URL to a public tunnel URL). Blind OOB cannot be confirmed."}]}
        if (args.get("action") or "mint").lower() == "mint":
            tok, url = _oobmod.mint_url(_oob_public)
            return {"content": [{"type": "text", "text": f"[oob] inject this URL into the sink, "
                    f"then `oob` action=check token={tok}:\n{url}"}]}
        tok = (args.get("token") or "").strip()
        hs = _oobmod.poll(_oob_local, tok)
        if hs:
            lines = "\n".join(f"  {h['method']} {h['path']} from {h['remote']} ua={h['ua'][:40]}"
                              for h in hs[:8])
            return {"content": [{"type": "text", "text": f"[oob] CONFIRMED — {len(hs)} "
                    f"interaction(s) on {tok}; the target reached out:\n{lines}"}]}
        return {"content": [{"type": "text", "text": f"[oob] no interactions on {tok} yet — sink "
                f"did not reach out (not confirmed)."}]}

    @tool("authz_matrix", "Cross-user authorization sweep (Autorize-style) in ONE call: replays a "
          "request across auth contexts x resource ids and flags broken access control. `url` must "
          "contain {id}; `auths` is a JSON object name->header (add \"anon\":\"\" for unauth); `ids` "
          "is comma-separated; put privileged contexts in `admins` so expected admin access isn't "
          "flagged; optional `owner` maps id->owning-context for precise BOLA detection. Set "
          "`neighbors` (e.g. 2) to auto-forge each id's sibling ids IN ITS OWN ENCODING (raw int, "
          "hex, base64, GraphQL global-node base64(\"Type:123\")) and test them — a single non-owner "
          "2xx on a forged neighbor is a BOLA hit. Flags anon-2xx (auth bypass) and non-owner 2xx "
          "(IDOR/BOLA) — the highest-paid web class.",
          {"url": str, "method": str, "auths": str, "ids": str, "admins": str, "owner": str,
           "neighbors": int})
    async def authz_matrix_tool(args):
        return {"content": [{"type": "text", "text": authz_matrix.run(sb, args)}]}

    @tool("browser_verify", "Render a URL in a real (headless) browser and tell XSS EXECUTION from "
          "ESCAPING — the stored/DOM-XSS class the REST layer is blind to. FIRST plant a payload "
          "that, ON EXECUTION, writes a UNIQUE marker into the DOM (e.g. an onerror/onload that does "
          "document.documentElement.dataset.x='<marker>'), THEN call this with the URL that renders "
          "it and that same marker. Marker present in the rendered DOM => stored XSS confirmed. "
          "Optional live_hint: a substring proving the payload became live markup (parsed, not "
          "escaped). Renders host-side, so the URL must be in scope.",
          {"url": str, "marker": str, "live_hint": str})
    async def browser_verify_tool(args):
        import browser_verify as _bv
        url = args.get("url", "")
        if scope is not None:
            okc, why = scope.allows(url)
            if not okc:
                return {"content": [{"type": "text", "text": f"[browser_verify] refused — {why}"}]}
        return {"content": [{"type": "text", "text":
                _bv.verify(url, args.get("marker", ""), args.get("live_hint", ""))}]}

    @tool("exploit_server", "Drive a client-side exploit's DELIVER-TO-VICTIM half via an exploit "
          "server (academy-style). STORE an HTML/JS payload, DELIVER_TO_VICTIM, and read the ACCESS "
          "LOG where the victim's callback / exfiltrated cookie lands. Give `exploit_server` (its base "
          "URL, e.g. https://exploit-0aXX.exploit-server.net — must be in scope), `body` (the payload "
          "HTML/JS), optional `path` (default /exploit), `head`, and `action` (store|deliver|log|all). "
          "For a REAL program there is no victim button — prove execution with browser_verify instead.",
          {"exploit_server": str, "body": str, "path": str, "head": str, "action": str, "https": str})
    async def exploit_server_tool(args):
        import exploit_server as _es
        base = args.get("exploit_server") or args.get("url") or ""
        if scope is not None and base:
            okc, why = scope.allows(base)
            if not okc:
                return {"content": [{"type": "text", "text": f"[exploit_server] refused — {why}"}]}
        return {"content": [{"type": "text", "text": _es.run(sb, args)}]}

    @tool("endpoint_recon", "Enumerate the target's endpoints (mines JS bundles + source maps) and "
          "FLAG the weird/forgotten ones — legacy, admin, debug, internal, undocumented — the "
          "endpoints a company left untouched, where bugs hide. Auto-banks the top interesting ones "
          "as LEADS so they persist and get pressed hard. Give the target url.",
          {"url": str, "max_bundles": int})
    async def endpoint_recon_tool(args):
        from recon import mine_js_endpoints, flag_interesting
        url = args.get("url") or ""
        mined = mine_js_endpoints(sb, url, int(args.get("max_bundles") or 6))
        paths = [ln.strip() for ln in mined.splitlines() if ln.strip().startswith("/")]
        flagged = flag_interesting(paths)
        for p, _score, reasons in flagged[:8]:     # bank the weird ones (persist + press hard)
            sp.add_lead(f"weird/forgotten endpoint {p}", "press hard: " + ",".join(reasons), url)
        if not flagged:
            return {"content": [{"type": "text", "text": (mined or "[endpoint_recon] no JS "
                    "endpoints mined") + "\n[endpoint_recon] nothing stood out to press on."}]}
        rep = "\n".join(f"  [{s}] {p}  ({','.join(r)})" for p, s, r in flagged[:15])
        return {"content": [{"type": "text", "text": mined + "\n\n== INTERESTING ENDPOINTS "
                "(banked as leads — PRESS HARD on these weird/untouched ones) ==\n" + rep}]}

    @tool("subdomain_recon", "Enumerate the target's subdomains via Certificate Transparency "
          "(crt.sh — passive, no traffic to the target) and sweep the IN-SCOPE ones for LIVE + "
          "EXPOSED-ORIGIN hosts (Server not a CDN => the WAF/CDN is bypassed, forgotten surface "
          "where bugs survive) and weird names (staging/uat/legacy/admin). Auto-banks the standouts "
          "as leads. Give the apex domain, e.g. example.com.", {"domain": str})
    async def subdomain_recon_tool(args):
        from recon import enum_subdomains, sweep_hosts, flag_interesting
        dom = (args.get("domain") or "").strip().lstrip("*.")
        if not dom:
            return {"content": [{"type": "text", "text": "subdomain_recon: give an apex domain."}]}
        subs = enum_subdomains(dom)
        if not subs:
            return {"content": [{"type": "text", "text": f"subdomain_recon {dom}: CT lookup "
                    "returned nothing (crt.sh may be rate-limiting; retry)."}]}
        if scope is not None:                       # only sweep hosts the scope authorizes
            subs = [s for s in subs if scope.allows("https://" + s + "/")[0]]
        subs = subs[:150]
        res = sweep_hosts(subs, header=id_header)
        exposed = [r for r in res if r.get("exposed")]
        live = [r["host"] for r in res if r["status"] not in ("000", "ERR", "404")]
        flagged = flag_interesting(live)
        for r in exposed[:8]:                       # exposed origins are the top signal — bank them
            sp.add_lead(f"EXPOSED-ORIGIN {r['host']} (server={r['server']}, {r['status']})",
                        "not behind the WAF/CDN — press hard", dom)
        for h, _s, reasons in flagged[:6]:
            sp.add_lead(f"weird subdomain {h}", "press: " + ",".join(reasons), dom)
        lines = [f"  [EXPOSED] {r['host']:42} {r['status']} server={r['server'][:30]}" for r in exposed]
        lines += [f"  [flag {s}] {h}  ({','.join(rs)})" for h, s, rs in flagged[:12]]
        return {"content": [{"type": "text", "text": f"subdomain_recon {dom}: {len(subs)} in-scope "
                f"subs swept, {len(live)} live, {len(exposed)} EXPOSED origins (banked as leads — "
                f"PRESS HARD):\n" + ("\n".join(lines[:22]) or "  (nothing stood out)")}]}

    @tool("secret_scan", "Hunt LIVE leaked credentials in the target's own JS/assets with "
          "trufflehog --only-verified — the highest single-bounty yield. It ACTIVELY verifies each "
          "candidate against its provider, so a hit is a WORKING key, not regex noise. Give the "
          "target url. A hit: confirm it's in scope and REPORT — do an identity check only, never "
          "exercise the key's permissions.",
          {"url": str, "max_bundles": int})
    async def secret_scan_tool(args):
        from recon import secret_scan
        url = args.get("url") or ""
        if scope is not None:
            okc, why = scope.allows(url)
            if not okc:
                return {"content": [{"type": "text", "text": f"[secret_scan] refused — {why}"}]}
        out = secret_scan(sb, url, int(args.get("max_bundles") or 8))
        if "VERIFIED secret" in out:
            for ln in out.splitlines():
                if "[VERIFIED]" in ln:
                    sp.add_lead("leaked verified secret" + ln.split("[VERIFIED]")[1], "confirm scope + report", url)
        return {"content": [{"type": "text", "text": out}]}

    @tool("browser_session", "Drive a REAL authenticated headless browser (in-sandbox Playwright, "
          "through the enforced proxy) — the authenticated, JS-heavy surface curl/--dump-dom can't "
          "see. Carry the session via `headers` (e.g. 'Authorization: Bearer ...'), `cookies` "
          "('a=b; c=d'), and/or `storage` (JSON localStorage — many SPAs keep the JWT there). "
          "Returns the post-JS DOM, same-scope app links, and — key — every XHR/fetch the page "
          "fired (the REAL API surface to attack). For AUTHENTICATED stored/DOM XSS pass `marker` "
          "(the string your payload writes on execution). Optional `actions` = JSON list of "
          "{do:click|fill|wait,sel,val,ms} for a short click-through. Give an in-scope url.",
          {"url": str, "headers": str, "cookies": str, "storage": str, "actions": str,
           "marker": str, "live_hint": str, "timeout": int})
    async def browser_session_tool(args):
        import browser_session as _bs
        url = args.get("url") or ""
        if scope is not None:
            okc, why = scope.allows(url)
            if not okc:
                return {"content": [{"type": "text", "text": f"[browser_session] refused — {why}"}]}
        out = _bs.run(sb, args)
        for ln in out.splitlines():                 # bank discovered API endpoints as leads
            ln = ln.strip()
            if ln[:6].strip() in ("GET","POST","PUT","PATCH","DELETE","HEAD"):
                sp.add_lead("authenticated XHR endpoint " + ln, "attack this real API route", url)
        return {"content": [{"type": "text", "text": out}]}

    @tool("crawl", "Actively CRAWL a live in-scope app with katana and return reachable URLs, "
          "prioritizing PARAM-BEARING ones (?a=1&b=2) — the exact input dast_scan fuzzes. Use this "
          "to turn a bare origin into the populated URLs an attacker can hit (static JS-mining only "
          "gives route names). Banks the param URLs as leads. Give the target url; `depth` default 2.",
          {"url": str, "depth": int})
    async def crawl_tool(args):
        from recon import crawl
        url = args.get("url") or ""
        if scope is not None:
            okc, why = scope.allows(url)
            if not okc:
                return {"content": [{"type": "text", "text": f"[crawl] refused — {why}"}]}
        out = crawl(sb, url, int(args.get("depth") or 2))
        for ln in out.splitlines():                 # bank param URLs so dast_scan/next run reuses them
            u = ln.strip()
            if u.startswith("http") and "?" in u:
                sp.add_lead(f"param URL {u}", "fuzz with dast_scan", url)
        return {"content": [{"type": "text", "text": out}]}

    @tool("dast_scan", "ACTIVE fuzz in-scope URLs for reflected XSS / error SQLi / LFI / SSTI / "
          "open-redirect / CRLF via nuclei's DAST templates — finds the injectable params the "
          "signature scan misses. Feed PARAM-BEARING urls (comma/newline list, from endpoint_recon "
          "or JS mining); a bare origin fuzzes little. Hits are LEADS: reproduce + prove impact "
          "before reporting. Blind/OOB classes need the `oob` tool (interactsh is unreachable under "
          "enforced egress). `rate` from the engagement RoE.",
          {"urls": str, "rate": int})
    async def dast_scan_tool(args):
        from recon import nuclei_dast
        urls = args.get("urls") or ""
        if scope is not None:                       # every url must be in scope
            for u in urls.replace(",", "\n").split():
                u = u.strip()
                if u.startswith("http"):
                    okc, why = scope.allows(u)
                    if not okc:
                        return {"content": [{"type": "text", "text": f"[dast_scan] refused — {why}"}]}
        return {"content": [{"type": "text", "text": nuclei_dast(sb, urls, int(args.get("rate") or 8))}]}

    @tool("race", "Test a limited action for a RACE CONDITION (TOCTOU): fires requests as "
          "simultaneously as possible and flags when the limited action succeeded MORE than allowed "
          "(coupon reused, balance overdrawn, quota/rate bypassed, invite over cap, partial-construction "
          "auth bypass). For https it uses the HTTP/2 single-packet attack automatically (one "
          "connection, all last bytes flushed together — wins sub-ms windows thread bursts miss); "
          "mode=h2|threads to force. SIMPLE: pass url+method+body+headers+n to fire N IDENTICAL "
          "requests. MULTI-STEP (do NOT hand-roll h2 — use this): pass `requests` = a JSON array of "
          "distinct {method,path,headers,body} fired together in ONE packet (e.g. [register, confirm, "
          "confirm] for a partial-construction race, or two different endpoints for a multi-endpoint "
          "TOCTOU), still relative to `url`'s host. Optional `prep` = a JSON {method,path,headers,body} "
          "sent+completed BEFORE the burst to establish a session (its Set-Cookie is applied to burst "
          "requests). State-changing — only what you pass is sent; confirm the side effect persisted.",
          {"url": str, "method": str, "body": str, "headers": str, "n": int,
           "expect_success": int, "success_re": str, "mode": str, "requests": str, "prep": str})
    async def race_tool(args):
        return {"content": [{"type": "text", "text": race.run(sb, args)}]}

    @tool("mass_assign", "Test MASS ASSIGNMENT: injects privileged fields (role/is_admin/verified/"
          "org_id/balance/plan) into a write request and RE-READS the object to prove they persisted "
          "(not just echoed). Give the write `url`+`method`(PATCH/PUT/POST), the base `body`, auth "
          "`headers`, and a `readback_url` (GET) if different. Custom `fields` (JSON) override the "
          "defaults. A stuck privileged field is the finding — then prove the privilege it grants.",
          {"url": str, "method": str, "body": str, "fields": str, "readback_url": str, "headers": str})
    async def mass_assign_tool(args):
        return {"content": [{"type": "text", "text": mass_assign.run(sb, args)}]}

    @tool("graphql", "Introspect a GraphQL endpoint and surface the ATTACKABLE surface: state-changing "
          "mutations, PII/secret fields, and node(id:)/*ById resolvers (the BOLA vector). Introspection "
          "alone is not a finding — this turns it into the authz tests that ARE (feed the node ids to "
          "authz_matrix; test each hot mutation unauthenticated/cross-user). Give the /graphql url + "
          "auth headers.", {"url": str, "headers": str, "query": str})
    async def graphql_tool(args):
        return {"content": [{"type": "text", "text": gql.run(sb, args)}]}

    @tool("xxe", "Mint XML external-entity (XXE) payloads (classic file-read, php-filter base64, SVG/"
          "XInclude wrappers, blind-OOB, parameter-entity exfil) and optionally fire one at an "
          "XML-parsing endpoint. For BLIND XXE, mint an oob URL first and pass it as `oob_url`, inject "
          "the blind-oob payload, then check the oob token. Read-only: targets a benign file "
          "(/etc/hostname); prove the class, don't exfil secrets. Give `mode` (file/oob/exfil/all), "
          "optional `url` to fire, `target` file, `oob_url`.",
          {"mode": str, "url": str, "target": str, "oob_url": str, "content_type": str, "headers": str})
    async def xxe_tool(args):
        return {"content": [{"type": "text", "text": xxe.run(sb, args)}]}

    @tool("smuggle", "DETECT HTTP request smuggling / desync via the timing-differential probe (CL.TE "
          "and TE.CL): a crafted request that makes the back-end hang waiting for a body the front-end "
          "already ended => the two disagree on request length (critical class). Detection ONLY — it "
          "does not poison shared traffic; a hang is a strong lead to confirm + report. Give the "
          "in-scope target url.", {"url": str, "timeout": float})
    async def smuggle_tool(args):
        if scope is not None:
            okc, why = scope.allows(args.get("url") or "")
            if not okc:
                return {"content": [{"type": "text", "text": f"[smuggle] refused — {why}"}]}
        return {"content": [{"type": "text", "text": smuggle.run(sb, args)}]}

    @tool("protopollute", "Test PROTOTYPE POLLUTION: injects __proto__ / constructor.prototype "
          "gadgets (JSON, query, form carriers) and reads a SEPARATE object to confirm the marker "
          "was inherited globally (real pollution, not reflection). A confirmed pollution flips "
          "app-wide defaults (isAdmin/auth/template). On a CONFIRMED pollution it hands you the "
          "ESCALATION GADGET catalog (reflected-property exfil, outbound-request redirect, "
          "NODE_OPTIONS/execArgv/EJS RCE, status flip) — fire the one matching the sink to weaponize. "
          "Give a JSON-merge/config `url`, optional `readback_url`, `headers`, `oob` (collaborator host "
          "for the exfil/RCE gadgets). Omit url to just mint payloads + the gadget menu.",
          {"url": str, "readback_url": str, "marker": str, "headers": str, "oob": str})
    async def protopollute_tool(args):
        return {"content": [{"type": "text", "text": protopollute.run(sb, args)}]}

    @tool("deserialize", "INSECURE DESERIALIZATION helper: fingerprints a serialized blob's format "
          "(Java/PHP/Python-pickle/Ruby/.NET/node-serialize) from a cookie/hidden-field/param and "
          "hands back the right benign detection/OOB probe for that stack. Confirm blind deser "
          "out-of-band (pair with `oob`). Give the `blob` you found (raw or base64), optional "
          "`oob_url`, and a `response` sample to flag deserialization error tells.",
          {"blob": str, "format": str, "oob_url": str, "response": str})
    async def deserialize_tool(args):
        return {"content": [{"type": "text", "text": deserialize.run(sb, args)}]}

    @tool("chain_scan", "Compose your banked primitives into a CRITICAL. Reads every lead/fact you've "
          "confirmed and matches them against canonical chain templates (SSRF->metadata->IAM, "
          "open-redirect->OAuth->ATO, IDOR->admin->RCE, upload+traversal->RCE, ...); returns READY "
          "chains and one-hop-away chains with the concrete next step. RULE: a lone SSRF/IDOR/"
          "open-redirect/XSS is a LEAD, not a finding — chain it or prove real impact first. Call "
          "this whenever you've confirmed 2+ primitives.", {})
    async def chain_scan(args):
        import chain as _chain
        leads = list(sp.leads) + [f"{k}={v}" for k, v in sp.facts.items()]
        return {"content": [{"type": "text", "text": _chain.render(_chain.find_chains(leads))}]}

    return create_sdk_mcp_server(name="ctf", version="1.0",
                                 tools=[sandbox_bash, note, lead, jwt_forge_tool, blind_extract_tool,
                                        time_blind_tool, ssrf_recon_tool, oob_tool,
                                        authz_matrix_tool, browser_verify_tool, exploit_server_tool,
                                        endpoint_recon_tool, subdomain_recon_tool,
                                        crawl_tool, secret_scan_tool, dast_scan_tool,
                                        browser_session_tool, race_tool, mass_assign_tool,
                                        graphql_tool, xxe_tool, smuggle_tool,
                                        protopollute_tool, deserialize_tool,
                                        chain_scan]), fp, sp


def _start_enforcement(config_path: str, image: str = SANDBOX_IMAGE,
                       engagement: bool = False):
    """No-bypass egress: internal-only network + an allowlisting proxy that is the
    agent's ONLY route out. With engagement=True the proxy enforces the full RoE
    (live expiry + kill switch), not just the host allowlist. Returns
    (network_name, proxy_url, cleanup)."""
    net = f"bnet_{uuid.uuid4().hex[:8]}"
    proxy = f"bproxy_{uuid.uuid4().hex[:8]}"
    flag = "--engagement" if engagement else "--scope"
    subprocess.run(["docker", "network", "create", "--internal", net],
                   check=True, capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", proxy, "--network", net,
                    "-v", f"{Path.cwd()}:/work", "-w", "/work", image,
                    "python3", "egress_proxy.py", flag, f"/work/{config_path}",
                    "--port", "8888"], check=True, capture_output=True)
    subprocess.run(["docker", "network", "connect", "bridge", proxy],
                   check=True, capture_output=True)  # only the proxy gets internet
    time.sleep(3)
    ip = subprocess.check_output(
        ["docker", "inspect", "-f",
         '{{(index .NetworkSettings.Networks "' + net + '").IPAddress}}', proxy]
    ).decode().strip()

    def cleanup():
        subprocess.run(["docker", "rm", "-f", proxy], capture_output=True)
        subprocess.run(["docker", "network", "rm", net], capture_output=True)
    print(f"[enforce] internal net {net}, egress only via proxy {ip}:8888")
    return net, f"http://{ip}:8888", cleanup


def _html_to_text(raw: str) -> str:
    """Crude HTML -> text: drop script/style, strip tags, unescape, collapse whitespace. Good
    enough to feed a doc to the LLM (it tolerates messy text); not a real parser."""
    import html as _html
    t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", raw or "")
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    return _html.unescape(re.sub(r"\s+", " ", t)).strip()


def _fetch_docs(urls: list[str], cap: int = 6000) -> str:
    """Fetch the target's OWN public docs (host-side, not through the agent's scoped proxy —
    reading public docs isn't testing, and the doc host is usually out-of-scope-to-test). Returns
    a labeled, truncated text block the agent turns into security invariants to hunt against."""
    import urllib.request
    blocks = []
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "bugbounty-research"})
            raw = urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
            blocks.append(f"### DOC {u}\n{_html_to_text(raw)[:cap]}")
        except Exception as e:
            blocks.append(f"### DOC {u}\n[fetch failed: {e}]")
    return "\n\n".join(blocks)


def _recon_sweep(sb, target: str, rate: int = 6) -> str:
    """DETERMINISTIC recon that ALWAYS runs before the agent — the arsenal (JS-mining, katana crawl,
    nuclei -dast, secret_scan) fired for real, not left to the model (which skips it: a live run did
    9 curls and 0 recon tools). Returns a block seeded into the agent so it starts from mapped surface
    + any dast hits and goes straight to pressing them."""
    from recon import mine_js_endpoints, crawl, nuclei_dast, secret_scan
    out = ["== AUTOMATED RECON (already executed against the in-scope target — build on this, do NOT "
           "re-run these tools; go straight to pressing the param URLs and any dast/secret hits) =="]
    def _step(label, fn):
        try:
            out.append(f"[{label}]\n" + (str(fn()) or "(nothing)")[:2500])
        except Exception as e:
            out.append(f"[{label}] error: {str(e)[:150]}")
    _step("endpoint_recon (JS/source mining)", lambda: mine_js_endpoints(sb, target))
    crawled = {"t": ""}
    def _crawl():
        crawled["t"] = crawl(sb, target, depth=2, rate=rate) or ""
        return crawled["t"]
    _step("crawl (katana — param-bearing URLs)", _crawl)
    param_urls = "\n".join(l for l in crawled["t"].splitlines() if "?" in l)[:4000] or target
    _step("dast_scan (nuclei -dast on the crawled params)", lambda: nuclei_dast(sb, param_urls, rate))
    _step("secret_scan (trufflehog on JS bundles)", lambda: secret_scan(sb, target))
    return "\n\n".join(out)


async def hunt(scope: Scope, target: str, backend: str = "docker",
               max_turns: int = 40, scope_path: str | None = None,
               enforce: bool = False, parallel_recon: bool = False,
               extra_roe: str = "", seed_auth: str = "", docs_text: str = "",
               id_header: str = "", wall_cap_s: int = 0) -> dict:
    ok, reason = scope.allows(target)
    print(f"[scope] {target}: {'ALLOWED' if ok else 'REFUSED'} — {reason}")
    if not ok:
        raise SystemExit(f"Refused by scope guardrail: {reason}")

    import os
    os.environ["CTF_SANDBOX"] = backend
    # epoch-second + short uuid: parallel runs launched in the same second must not share a dir
    # (they did — a simultaneous PortSwigger pair clobbered each other's findings.md/audit.jsonl).
    workdir = (Path("bounty_runs") / f"{int(time.time())}-{uuid.uuid4().hex[:6]}").resolve()
    (workdir / "files").mkdir(parents=True, exist_ok=True)

    net_name = proxy_url = None
    cleanup = lambda: None
    if enforce:
        net_name, proxy_url, cleanup = _start_enforcement(scope_path)

    try:
        with make_sandbox(workdir / "files", network=True,
                          network_name=net_name, proxy_url=proxy_url) as sb:
            if id_header and ":" in id_header:   # identifying header on every curl (H1 dedup)
                safe = id_header.replace('"', "").replace("'", "").strip()
                sb.bash("printf 'header = \"%s\"\\n' '" + safe + "' > \"$HOME/.curlrc\"")
            ctf_srv, footprint, sp = _server(sb, scope, id_header)
            import memory
            campaign = memory.campaign_recall(target)   # prior runs on THIS exact target
            from solver import _knowledge_server
            opts = ClaudeAgentOptions(
                system_prompt=BOUNTY_SYS + extra_roe,
                mcp_servers={"ctf": ctf_srv, "kb": _knowledge_server()},
                allowed_tools=["mcp__ctf__sandbox_bash", "mcp__ctf__note", "mcp__ctf__lead",
                               "mcp__ctf__jwt_forge", "mcp__ctf__blind_extract",
                               "mcp__ctf__time_blind", "mcp__ctf__ssrf_recon", "mcp__ctf__oob",
                               "mcp__ctf__authz_matrix", "mcp__ctf__browser_verify",
                               "mcp__ctf__exploit_server",
                               "mcp__ctf__endpoint_recon", "mcp__ctf__subdomain_recon",
                               "mcp__ctf__crawl", "mcp__ctf__secret_scan",
                               "mcp__ctf__dast_scan", "mcp__ctf__browser_session",
                               "mcp__ctf__race", "mcp__ctf__mass_assign",
                               "mcp__ctf__graphql", "mcp__ctf__xxe", "mcp__ctf__smuggle",
                               "mcp__ctf__protopollute", "mcp__ctf__deserialize",
                               "mcp__ctf__chain_scan",
                               "mcp__kb__search_knowledge"],
                max_turns=max_turns, model=MODEL)
            recon_turns, recon_cost, recon_map = 0, 0.0, ""
            usages = []  # raw ResultMessage.model_usage dicts for token-based costing
            if parallel_recon:
                from recon_agents import parallel_recon as _precon
                ctx = (f"Program: {scope.program}. In-scope: {', '.join(scope.in_scope)}. "
                       f"Rate limit ~{scope.rate_limit_rps} req/s."
                       + (f"\nAUTH — reuse this header to map the AUTHENTICATED surface too:\n"
                          f"{seed_auth}" if seed_auth else "") + extra_roe)
                pr = await _precon(sb, target, ctx)
                recon_turns, recon_cost, recon_map = pr["turns"], pr["cost"], pr["map"]
                usages.extend(pr.get("usages", []))
                print(f"[parallel-recon] {recon_turns} turns, ${recon_cost}, "
                      f"{pr['wall_s']}s across {len(pr['areas'])} subagents")
            det_recon = ""
            if not parallel_recon:            # parallel_recon already maps the surface via subagents
                print("[recon] deterministic sweep: JS-mining -> crawl -> nuclei -dast -> secret_scan …")
                det_recon = _recon_sweep(sb, target, rate=max(1, int(scope.rate_limit_rps * 4)))
                print(f"[recon] sweep done ({len(det_recon)} chars seeded to the agent)")
            task = (f"Authorized target: {target}\nProgram: {scope.program}\n"
                    f"In-scope hosts: {', '.join(scope.in_scope)}\n"
                    f"Rate limit: ~{scope.rate_limit_rps} req/s.\n\n"
                    + (f"{det_recon}\n\n" if det_recon else "")
                    + (f"{campaign}\n\n" if campaign else "")
                    + (f"SEED AUTH — you have an authenticated session on this OWN trial site. "
                       f"Reuse this exact header on EVERY request to test authenticated, "
                       f"object-level surface (IDOR/BOLA, share/bundle/inbox access control, "
                       f"mass assignment):\n{seed_auth}\n\n" if seed_auth else "")
                    + (f"A recon team already mapped the attack surface — start from "
                       f"this and go straight to exploitation, don't re-enumerate:\n"
                       f"{recon_map}\n\n" if recon_map else "")
                    + (f"TARGET DOCUMENTATION — derive the security INVARIANTS this product "
                       f"promises (who may do what, what is isolated between users/tenants, what "
                       f"is enforced/validated) and hunt where the IMPLEMENTATION VIOLATES them. "
                       f"A divergence from documented behavior is the highest-signal finding class "
                       f"and how mature programs judge validity — cite the doc line for any "
                       f"finding:\n{docs_text}\n\n" if docs_text else "")
                    + "Recon the target, then enumerate and safely confirm vulnerabilities. "
                    "Summarize every finding at the end.")
            thoughts, turns, cost = [], 0, None
            _run_start = time.time()
            try:
                async for msg in query(prompt=task, options=opts):
                    if wall_cap_s and time.time() - _run_start > wall_cap_s:
                        print(f"[budget] wall-clock cap {wall_cap_s}s reached — finalizing from the "
                              f"trace so far (findings + leads + campaign memory are still written)")
                        break
                    if isinstance(msg, AssistantMessage):
                        turns += 1
                    if isinstance(msg, ResultMessage):
                        if msg.total_cost_usd:
                            cost = msg.total_cost_usd
                        if msg.model_usage:
                            usages.append(msg.model_usage)
                    for b in getattr(msg, "content", []) or []:
                        if isinstance(b, TextBlock):
                            thoughts.append({"t": time.time(), "kind": "thought", "text": b.text})
            except Exception as e:
                # The SDK RAISES on max_turns (documented gotcha). A deep run that spends its whole
                # budget HAS a full trace — finalize gracefully (report + campaign memory + leads)
                # instead of crashing and losing everything. Any OTHER error (e.g. the API cyber
                # safeguard) still surfaces as a failure.
                if "maximum number of turns" not in str(e):
                    raise
                print(f"[max-turns] agent used all {max_turns} turns — finalizing from the "
                      f"trace so far (findings + leads + campaign memory are still written)")
            trace = sorted(sb.actions + thoughts, key=lambda e: e["t"])
            memory.record_campaign(target, sp.dump())   # accumulate per-target model for next run
    finally:
        cleanup()

    save_audit(workdir / "audit.jsonl", trace)
    report = await generate_report(scope.program, target, trace)
    (workdir / "findings.md").write_text(report)
    from validate import validate_report            # gate weak/decoy/never-submit findings
    _annotated, _vsum = validate_report(report)
    (workdir / "findings_validated.md").write_text(_annotated)
    print(f"[validate] {_vsum['validated']} validated / {_vsum['rejected']} rejected of "
          f"{_vsum['findings']} finding(s)")
    # wall-clock speed of the assessment, from the trace timestamps
    ts = [e["t"] for e in trace if "t" in e]
    duration_s = round(ts[-1] - ts[0], 1) if len(ts) > 1 else None
    total_turns = turns + recon_turns
    total_cost = (cost or 0) + recon_cost if (cost or recon_cost) else None
    from pricing import summarize
    usage = summarize(usages)  # token-based, self-verifiable cost from raw token counts
    row = {"time": time.time(), "program": scope.program, "target": target,
           "turns": total_turns, "cost_usd": total_cost, "duration_s": duration_s,
           "parallel_recon": parallel_recon,
           "recon_turns": recon_turns, "exploit_turns": turns,
           "tokens": usage["tokens"],
           "cost_recomputed_usd": usage["cost_recomputed_usd"],
           "cost_sdk_usd": usage["cost_sdk_usd"],
           "footprint": footprint,
           "report": str(workdir / "findings.md")}
    with open(METRICS, "a") as f:
        f.write(json.dumps(row) + "\n")
    dur = f", {duration_s:.0f}s" if duration_s else ""
    split = f" ({recon_turns} recon + {turns} exploit)" if parallel_recon else ""
    tk = usage["tokens"]
    print(f"[done] {total_turns} turns{split}{dur}; "
          f"tokens in/out {tk['input']}/{tk['output']} "
          f"(+{tk['cache_read']} cache); cost ${usage['cost_recomputed_usd']} "
          f"recomputed / ${usage['cost_sdk_usd']} sdk; findings -> {workdir/'findings.md'}")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True, help="authorization/scope JSON file")
    ap.add_argument("--target", required=True, help="in-scope target URL")
    ap.add_argument("--backend", default="docker")
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--enforce", action="store_true",
                    help="no-bypass egress: run the agent on an internal-only network "
                         "whose sole route out is the scope-allowlisting proxy")
    ap.add_argument("--parallel-recon", action="store_true",
                    help="fan out read-only recon subagents to map the surface first, "
                         "then exploit from that map (helps broad targets)")
    ap.add_argument("--roe", help="file with extra program-specific rules of engagement "
                    "(stopping rules, banned features), appended to the agent prompt")
    ap.add_argument("--auth-env", help="name of an env var holding a seed auth header "
                    "(e.g. 'X-FilesAPI-Key: ...') reused for every request; keeps the "
                    "secret out of argv/ps")
    ap.add_argument("--docs", help="comma-separated PUBLIC doc URLs; fetched host-side and fed to "
                    "the agent to derive security invariants and hunt divergence from them")
    ap.add_argument("--id-header", help="identifying header (e.g. 'X-HackerOne-Research: user') "
                    "written into the sandbox curlrc so it rides on every curl (program dedup)")
    ap.add_argument("--wall-cap", type=int, default=0, help="hard wall-clock budget in seconds; "
                    "the run finalizes gracefully when hit (research: cost<->success correlate "
                    "inversely — a good solver wins fast). 0 = no cap (max_turns only)")
    args = ap.parse_args()
    import os as _os
    roe = ("\n\n" + Path(args.roe).read_text()) if args.roe else ""
    seed = _os.environ.get(args.auth_env, "") if args.auth_env else ""
    docs = _fetch_docs([u.strip() for u in args.docs.split(",") if u.strip()]) if args.docs else ""
    asyncio.run(hunt(Scope.load(args.scope), args.target, args.backend,
                     args.max_turns, scope_path=args.scope, enforce=args.enforce,
                     parallel_recon=args.parallel_recon, extra_roe=roe, seed_auth=seed,
                     docs_text=docs, id_header=args.id_header or "", wall_cap_s=args.wall_cap))


if __name__ == "__main__":
    main()
