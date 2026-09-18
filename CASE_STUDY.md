# Case Study — Deploying an Autonomous Security Agent Against an Unfamiliar Target

*How ctf-agent goes from "here is a host you have never seen" to a client-ready
vulnerability report, and what it costs.*

This is the deliverable an offensive-security team actually ships: not a solved
puzzle, but a **finding, reproduced, scored, and written up for the customer** —
produced against a target the system had no prior knowledge of.

---

## The scenario

Point the system at an authorized target with zero hand-holding:

```bash
python bounty.py --scope scope.json --target http://<authorized-host> --enforce
```

`--enforce` routes all agent egress through an allowlisting proxy on an
internal-only Docker network, so the agent **physically cannot** touch anything
outside the declared scope — the network layer enforces authorization, not a
prompt. Recon runs, the orchestrator picks a specialist, the specialist exploits,
the verifier confirms, and `report.py` emits a HackerOne/Bugcrowd-format writeup.

## What it produced — OWASP Juice Shop (authorized instance)

One run, no prior knowledge of the app, read-only testing:

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | SQL injection auth bypass (`POST /rest/user/login`) | **Critical (9.8)** | CWE-89 |
| 2 | UNION SQLi — full credential dump (`GET /rest/products/search`) | **Critical** | CWE-89 |
| 3 | Poison null-byte file-filter bypass (`GET /ftp/`) | High | CWE-22 |
| 4 | IDOR — other customers' baskets (`GET /rest/basket/{id}`) | High | CWE-639 |
| 5–8 | Excessive data exposure, unauth'd docs, open `/metrics`, verbose SQL errors | Med–Low | — |

Each finding ships with CVSS 3.1 vector, affected asset, copy-pasteable repro
steps, impact, and remediation. Full report: [docs/juiceshop_findings.md](docs/juiceshop_findings.md).

## The unit economics (measured, not estimated)

From `results/bounty_metrics.jsonl` (SDK-reported cost — see pricing.py for the token-based cross-check caveat):

| Run | Target | Turns | Cost | Output |
|---|---|---|---|---|
| Self-demo lab | own SQLi target | 25 | **$0.66** | full findings report |
| Juice Shop | own instance | 21 | **$0.62** | 8 findings, 2 Critical |
| VAmPI (3rd-party API) | own instance | 27 | **$1.01** | 6 findings, 4 Critical, 138s |

**~$0.60–0.66 and ~20–25 model turns to go from unknown host → written report.**
On the CTF benchmark the exploit step itself lands in a median **~8–19s** once
recon briefs the specialist (many crypto/forensics tasks solve in a single
zero-turn recon pass, at no model cost at all).

The FDE-relevant number isn't "it works" — it's *what value per dollar, at what
speed, with what auditability*. Every run leaves a timestamped `audit.jsonl` so
the cost and every action are accountable after the fact.

## Why this maps to Forward-Deployed work

- **Unknown environment, fast value.** The system adapts to a target it has never
  seen and produces a customer-ready artifact — the core FDE motion.
- **Business framing, not just a hack.** Output is a severity-ranked report a
  stakeholder can act on, with remediation — the thing that gets paid for.
- **Trust boundaries built in.** Network-layer scope enforcement + an
  always-deny list (cloud metadata, `.gov`/`.mil`) means it's deployable without
  becoming a liability.
- **Accountable.** Ground-truth audit log per run; the model can't claim a step
  it didn't take.

## Honest limits

- Cost capture (`cost_usd`) is populated by the SDK on some paths but not all;
  the per-finding economics above come from the bounty runs where it is reliable.
- Findings to date are against **authorized** targets (own lab, own Juice Shop
  instance). A real external bug-bounty run is gated on a program that permits
  automated testing plus an explicit declared scope — deliberately not run
  without that authorization.
