# Authorized adversary-emulation mode — containment architecture

Goal: run realistic attacker techniques (so engagements surface real blind spots) while making
it **impossible for the agent to act outside the authorized scope** and **impossible to hide
what it did**. Realism inside a cage. This is the design for turning breachswarm into a red-team /
purple-team agent, and the boundary that keeps it legitimate.

## "The assassin cannot escape scope" — defense in depth
No single check is trusted. Three independent layers, each of which alone would stop an
out-of-scope action:

**Layer 1 — Policy (refuses).** `engagement.py` (`Engagement`, an RoE-grown-up `Scope`):
- host allowlist + always-deny (metadata / `.gov` / `.mil` / localhost) — inherited from `scope.py`
- **mandatory expiry** (load fails without one — no open-ended authorization) + optional start window
- **explicit technique allowlist** (ATT&CK ids/classes; `["*"]`=all, `[]`=none)
- **loudness budget** (max actions/hour) so "realistic" never means "reckless"
- **destructive OFF by default** (use canary tokens, never real data/exfil)
- **out-of-band kill switch** (a file path; present ⇒ abort)

**Layer 2 — Network (the hard wall).** `--enforce` (`egress_proxy.py`): the agent runs on an
**internal-only Docker network** whose *only* route out is a proxy that checks every request
against scope. An out-of-scope request fails at the socket layer — the agent cannot reach a
non-scope host even if a prompt-injection, a bug, or a confused plan tells it to. Validated end
to end in `docs/golive_dryrun.md`. The proxy now also enforces the full `Engagement`
(`--engagement`): expiry and the kill switch are re-checked on **every request**, so the wire is
cut mid-run the instant authorization ends or the kill switch trips — even for in-scope hosts,
regardless of what the agent tries.

**Layer 3 — Audit (records).** `audit_chain.py` (`AuditChain`): every action is appended to a
hash-chained, tamper-evident JSONL — edit or drop any past entry and `verify()` fails at that
seq. The agent evades the *target's* detection (the test); it hides *nothing* from the client's
debrief. A stealth red-team agent produces MORE evidence, not less. This is the exact inverse of
anti-forensics, and it's non-optional — if the log could be turned off, the model collapses.

## The boundary (legitimate emulation vs. malicious use)
Same techniques, different frame. What makes it legitimate, enforced above:
1. **Authorization** — a signed RoE, encoded and expiring, gates every action.
2. **Containment** — the network layer makes out-of-scope physically unreachable.
3. **Accountability** — the tamper-evident chain means the whole run is reviewable.
4. **No anti-forensics, no destruction** — the agent never destroys evidence or real data; it
   uses canaries. (This is also what keeps "document everything for research" *true*.)

Out of scope for this project, by design: anti-forensic / log-tampering capability, and evasion
hand-tuned to defeat a *specific named* defensive product purely for concealment — those work as
real intrusion tools regardless of stated intent, and the layers above are what keep us clear of
them. Everything short of that — realistic, ATT&CK-mapped techniques run under a live RoE with a
full audit — is fair game and is the point.

## Status & roadmap
- [x] `audit_chain.py` — tamper-evident hash-chained log (+ tests)
- [x] `engagement.py` — RoE engine: expiry, technique allowlist, loudness budget, kill switch (+ tests)
- [x] `egress_proxy.py --enforce` — network-layer scope containment (validated on Juice Shop)
- [x] **`Engagement` enforced at the proxy** (`--engagement`) — network-layer expiry + live kill
      switch: authorization ending or the kill switch tripping cuts egress mid-run
- [x] **ATT&CK technique registry + blue-team scorecard** (`techniques.py`) — `classify()`
      maps each payload to a MITRE technique + the control it tests; `outcome_from()` reads the
      target's own response (403/block = caught, 2xx to an evaded payload = gap); `scorecard()`
      + `render()` produce the defender table ("WAF blocked path traversal but MISSED evaded
      UNION SQLi → 🔴 detection gap"). The purple-team deliverable.
- [x] **No-destruction rail + canary tokens** (`safety.py`) — `guard_destructive` blocks data/
      availability destruction unless the RoE says `destructive: true` (wired into `bounty.py`);
      `canary_token` proves impact/exfil with nothing at risk. Deconfliction `announce()` writes
      run phases to a shared white-cell channel.
- [ ] **Engagement-aware runner** — thread `Engagement` + `AuditChain` + scorecard through a
      `bounty.py`-style entrypoint so a full run is authorized, contained, audited, and ends
      with the scorecard. (The pieces exist; this wires them into one command.)
