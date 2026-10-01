## Recon Methodology — how effective operators actually work
Skilled adversaries are effective because they are METHODICAL, not fast-and-loud. They build a
target model before touching anything and let each phase feed the next. Structure the engagement
this way instead of spraying payloads.

The phased chain (Lockheed Cyber Kill Chain / MITRE ATT&CK / Unified Kill Chain):
recon -> weaponize -> deliver -> exploit -> escalate/persist -> act on objective. Recon is not a
one-time step: it RE-FIRES every time a new surface, host, or privilege level appears.

MITRE ATT&CK Reconnaissance (TA0043) — the discipline, mapped to web:
- T1595 Active Scanning: fingerprint the stack and map the LIVE surface (status-coded), don't
  brute-force blind. Passive first (headers/cookies/JS/body), active only where it pays.
- T1592 Gather Victim Host Info: server, framework, language, versions -> known-CVE shortlist.
- T1590 Gather Network Info: hosts, ports, internal services revealed by SSRF/redirects.
- T1589/T1593/T1594/T1596 OSINT: victim-owned sites, source maps, open tech DBs, leaked creds.

OWASP WSTG Information Gathering — "map before you probe":
fingerprint web server -> identify framework/tech -> enumerate app entry points -> map execution
paths and roles -> identify the attack surface. Only then exploit. PTES calls this Intelligence
Gathering; the point is the same: enumeration precedes exploitation.

Why they are effective (the operator mindset — copy this):
- FINGERPRINT, THEN PICK A PLAYBOOK. A stack implies its bugs: Flask/Jinja -> SSTI/pickle;
  Node/Express -> prototype pollution/NoSQLi; Spring -> SpEL/deserialization/actuator; PHP -> LFI
  wrappers/object injection; Rails/Django JSON API -> IDOR/BOLA/mass-assignment; GraphQL ->
  introspection/batching; WordPress -> plugin CVEs/xmlrpc. Hunt what APPLIES; skip what doesn't.
- NEGATIVE SPACE IS DISCIPLINE. A 4-route JSON API is not a place to run a 1483-word directory
  list, a PHP/LFI hunt, or a WordPress scan. Every irrelevant request is wasted effort AND a
  detection signal. Match the technique to the archetype.
- LOW AND SLOW. Minimize footprint: one hypothesis-driven request beats a barrage; pace under
  rate limits; never re-probe a dead endpoint (404/403 tarpit); prefer evaded/low-signature
  payloads. A good operator is a ninja, not a bull — noise gets you caught and rate-limited.
- KEEP A TARGET DOSSIER. Record confirmed facts (params, encodings, valid ids, tokens, roles,
  internal hosts) and REUSE them; never reconstruct context or re-derive what you already proved.
  Each new privilege or surface = re-recon THAT surface with what you now hold (e.g. re-map as
  admin once you forge a token).
- HYPOTHESIS-DRIVEN, EVIDENCE-CORRECTED. Hold the fingerprint prior loosely: pursue the ranked
  tree first, but if it's exhausted without a win, widen out rather than treating the surface as
  fully understood.

Practical order for a web target: passive fingerprint (headers/cookies/body/JS) -> classify the
archetype -> load that archetype's playbook -> map live endpoints from links/JS/known routes ->
form ONE hypothesis and send the right request -> confirm with a minimal proof -> record the fact
-> escalate/chain -> re-recon each new surface. Enumerate from what the app reveals, not from a
wordlist, until mapping is exhausted.
