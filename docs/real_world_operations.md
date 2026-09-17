# Real-World Operations — Authorization, Enforcement, Targets

How the agent is run safely against real targets. Three layers, plus guidance on
what's legal to point it at.

## 1. Authorization (preflight) — `scope.py`

Every run loads a scope file and refuses any target that isn't:
- `authorized: true`, **and**
- matched by an `in_scope` host glob/CIDR, **and**
- not matched by `out_of_scope` or the built-in always-deny list (cloud-metadata
  `169.254.169.254`, `.gov`/`.mil`, shared infra).

Silence ≠ consent: no scope file, no run. Template: `scope.example.json`.

## 2. Egress enforcement (network layer) — `egress_proxy.py` + `bounty.py --enforce`

Preflight alone trusts the agent to stay in scope. `--enforce` removes that trust:

- The agent container runs on an **internal-only Docker network** (no external route).
- Its **sole** path out is an **allowlisting proxy** (`egress_proxy.py`) that re-checks
  every request (HTTP and HTTPS CONNECT) against the same scope and rate-limits it.
- Out-of-scope requests get `403`; direct (non-proxy) egress simply has no route.

**Verified:** on the internal network, direct egress → `000/blocked`, in-scope via
proxy → `200`, out-of-scope via proxy → blocked. The agent *cannot* reach anything
off-scope even if it tries.

```bash
./.venv/bin/python bounty.py --scope scope.json --target https://app.in-scope.com --enforce
```

## 3. Audit + reporting

Every run writes a full `audit.jsonl` (every command + output) and a professional
findings report (`report.py`, HackerOne/Bugcrowd format), and appends to the
`bounty_metrics.jsonl` success ledger.

## 4. What it's legal to point at (researched)

**Start with sanctioned practice targets** (blanket authorization, you own/are
permitted the instance) — this is the safe first ground for an autonomous agent:

1. **Your own OWASP Juice Shop instance** (Docker) — MIT, built as a scanner
   guinea-pig; total authorization since you host it. *Do not scan the shared public
   demo.* — the recommended first "real app" run.
2. **scanme.nmap.org** — publicly authorized for port scans only (no exploits, ~dozen
   scans/day).
3. **testphp.vulnweb.com** (Acunetix) / **Google Firing Range** — operator-blessed
   intentionally-vulnerable scanner testbeds.
4. **PortSwigger Web Security Academy**, **HackTheBox**, **TryHackMe**, **DVWA** —
   per-user authorized instances.

**Real programs that allow automation (with conditions) — only after reading the
brief:** Intigriti (2–10 req/s caps), Shopify, Google VRP, and HackerOne's
platform-level AI-assisted-testing allowance. Each program's brief governs and can
still restrict it. Precedent: the XBOW agent reached #1 on HackerOne US (2025).

**AI/LLM-specific:** huntr.com (Protect AI), and the major labs' AI bug bounties
(Anthropic, OpenAI, Google, etc.) — none advertise blanket automation; platform
rate/automation rules apply.

### Reading a policy — clauses that mean "automation allowed"
An explicit automated-scanning permission; a stated **rate-limit** (implicit
allow-with-limits — honor the number); an in-scope block; a **safe-harbor** clause
(what makes access "authorized" under the CFAA). Default when silent: **prohibited**
(Bugcrowd/YesWeHack reject raw scanner output outright).

### Hard "do not"
Don't scan shared public demos; don't touch a program silent on automation or any
out-of-scope asset; never exceed the stated req/s or run DoS/volumetric tests; never
submit raw agent output as a finding (validate + demonstrate impact); assumed
authorization is not authorization.

## Recommended first authorized run
Stand up **your own OWASP Juice Shop** locally and point the agent at it with
`--enforce`. It's a real, complex app, fully authorized, and needs no external
program — the honest bridge from our lab targets to real-world testing.
