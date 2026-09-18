# Go-Live dry-run — enforced pipeline vs OWASP Juice Shop

The `docs/GO_LIVE.md` pre-flight: prove the `--enforce` path end-to-end against a self-hosted
instance so the only remaining variable for a real engagement is program authorization.

## Setup
```bash
docker run -d --rm --name juice bkimminich/juice-shop      # own instance @ 172.17.0.2:3000
python bounty.py --scope scope.juice.json --target http://172.17.0.2:3000 --enforce --max-turns 40
```
`--enforce`: the agent ran on an **internal-only** Docker network (`bnet_…`) whose sole route
out was the scope-allowlisting proxy (`172.18.0.2:8888`). Every request was checked against
`scope.juice.json`; an out-of-scope host would have failed at the network layer.

## Result — 22 turns, 78s, $0.55 (SDK)
**7 findings written up (3 Critical), all reproduced live** — see
`juiceshop_enforced_findings.md`:
1. SQLi → auth bypass (`POST /rest/user/login`) — Critical
2. UNION SQLi → full credential dump (`GET /rest/products/search`) — Critical
3. Mass assignment → anonymous admin (`POST /api/Users`) — Critical
4. IDOR/BOLA cross-user basket read — High
5. Poison-null-byte path traversal (`/ftp/…`) — High
6. Unsalted-MD5 password storage — Medium
7. Verbose SQL error disclosure — Low

## Independent corroboration (not hallucinated)
Juice Shop's **own challenge tracker** logged the matching exploits as SOLVED during the run —
authoritative, app-side proof each exploit actually landed:
`loginAdminChallenge` (#1), `unionSqlInjectionChallenge` (#2), `registerAdminChallenge` (#3),
`basketAccessChallenge` (#4), `nullByteChallenge` (#5), `forgottenDevBackupChallenge`,
`errorHandlingChallenge` (#7), `passwordRepeatChallenge`. Every scored finding maps to a
Solved event.

> Note: Juice Shop's stdout does **not** log per-request `GET/POST` lines (only challenge-solve
> events), so "grep the access log" shows 0 requests even though the agent clearly hit it — use
> the Solved-challenge events as ground truth instead.

## Verdict
The enforced pipeline is **validated end-to-end**: scope gate → no-bypass egress proxy →
autonomous exploitation → corroborated client-ready report, in 78s for $0.55. The engineering
for a real engagement is done; the only remaining prerequisite is a program that **explicitly
permits automated testing** + a scope file + an explicit go-ahead (`docs/GO_LIVE.md`,
`docs/targets.md`).

Caveat: Juice Shop is *deliberately* vulnerable. A hardened production target will yield far
less and demands stricter false-positive discipline — "runs safely" ≠ "will find a paid bug".
