# Proving-ground & data-collection targets (authorized)

Research pass for where this system can *legally* run — for iteration/data collection
now, and for a real authorized bounty later. Ordered by how usable they are for THIS
project (autonomous, higher request volume than a human).

## TL;DR
- **Data collection / iteration →** self-host deliberately-vulnerable apps. Unlimited,
  controllable, zero ToS risk, and you own the flag so scoring is exact. This is where
  the system should do most of its learning.
- **Public "real-internet" validation →** the `vulnweb.com` family (Acunetix sanctions
  scanning them). Already used for two validations.
- **Real bug bounty (needs explicit automation permission + declared scope + user
  go-ahead) →** **Shopify** and **Google VRP** are the notable programs that permit
  *rate-limited* automation. Verify the live policy every time; `scope.py` + a human
  go-ahead gate this regardless.

## Tier 1 — Self-hosted, deliberately vulnerable (best for data collection)
Own the box, own the flag, no rate limits, no ToS. Canonical index: **OWASP VWAD**
(vwad.owasp.org) lists ~1000 of these.

| App | Focus | Stand up |
|-----|-------|----------|
| OWASP Juice Shop | broad OWASP Top 10, modern SPA | `docker run -d -p 3000:3000 bkimminich/juice-shop` |
| OWASP crAPI | **API / BOLA / mass-assignment / JWT** | `docker compose` (crAPI repo) |
| VAmPI | vulnerable REST API | `docker run -d -p 5000:5000 erev0s/vampi` |
| DVGA | **GraphQL** abuse | `docker run -d -p 5013:5013 dolevf/dvga` |
| OWASP WebGoat | guided lessons, Java | `docker run -d -p 8080:8080 webgoat/webgoat` |
| DVWA | classic PHP (SQLi/LFI/upload) | `docker run -d -p 80:80 vulnerables/web-dvwa` |
| Mutillidae II | XSS/SQLi/authz, hint-driven | OWASP image |
| bWAPP | 100+ bugs, OWASP Top 10 | `raesene/bwapp` |
| NodeGoat / RailsGoat | framework-specific Top 10 | project repos |
| Pixi | MongoDB **NoSQLi**, JWT | `docker` (Pixi repo) |
| Metasploitable 2/3 | full vulnerable host | VM |

These directly exercise the new RAG cards (GraphQL, NoSQLi, mass-assignment,
deserialization, prototype pollution). **Next data run:** crAPI + DVGA to stress the
API/GraphQL playbook and collect turns/footprint data.

## Tier 2 — Public, sanctioned to scan
- **vulnweb.com** — `testphp`, `testasp`, `testaspnet`, `rest.vulnweb.com`. Acunetix
  explicitly offers these for scanner testing. Public internet, so realistic latency /
  WAF-free baseline. *In scope for this project (user-approved).*
- **Google Gruyere** (`google-gruyere.appspot.com`) — Google's own web-sec codelab,
  intended to be attacked (per-instance).
- **Hack The Box / TryHackMe** — per-user instances you spin up; automation *inside your
  own instance* is fine. Great for pwn/rev/host targets, less for high-volume web scan.
- **PortSwigger Web Security Academy** — excellent labs, per-user instances, but they
  **discourage automated scanners** against lab infra; treat as manual-methodology
  reference, not an autonomous-agent target.

## Tier 3 — CTF corpora (offline, for RAG mining + benchmarking)
- **InterCode-CTF** (current headline benchmark, 100 tasks).
- **picoCTF** archives, **OverTheWire** wargames (Bandit/Natas/Krypton — automation on
  your own SSH session is fine), **pwn.college**, **CTFtime** writeup archive.
- Use these as *evaluation* and as *source material to mine into knowledge/ cards* — not
  as live external targets.

## Real bug bounty with automation permitted
Most programs **default to no automated scanning** unless the policy says otherwise.
Search results (Sep 2026) call out two that explicitly allow it:
- **Shopify** — automated testing allowed at a reasonable request rate.
- **Google VRP** — automated tools allowed; account suspended if you degrade service
  availability.
Process to qualify any program before pointing the agent at it:
1. Policy contains an explicit "automated testing/scanning is permitted" clause (not
   just silence).
2. Assets are clearly in-scope and listed in a `scope.json`.
3. A stated rate limit we can honor (the stealth circuit-breaker + rate control help).
4. Explicit user go-ahead for that specific run.
`scope.py` hard-refuses `authorized != true` and always-denies cloud metadata / `.gov` /
`.mil` / localhost, so a misconfigured target can't be hit even by mistake.

## How this maps to the roadmap
- **Now:** local (`targets/` incl. Fortress) + vulnweb. ✅
- **Next:** self-host crAPI + DVGA + Pixi → data runs that exercise the new
  API/GraphQL/NoSQL/mass-assignment cards; fold turns/footprint into tuning.
- **Go-live:** a Shopify- or Google-VRP-class program (policy re-verified) with
  `--enforce` egress isolation + rate limiting, staged in `docs/GO_LIVE.md`.

## Sources
- [OWASP Vulnerable Web Applications Directory](https://vwad.owasp.org/)
- [Geekflare — practice hacking legally](https://geekflare.com/cybersecurity/practice-hacking-legally/)
- [Recorded Future — vulnerable sites for pentest training](https://www.recordedfuture.com/threat-intelligence-101/vulnerability-management-threat-hunting/vulnerable-websites-for-penetration-testing)
- [Using automated scanning in bug bounties without getting banned](https://bug-bounties.as93.net/learn/automated-vulnerability-scanning-in-bounties/)
