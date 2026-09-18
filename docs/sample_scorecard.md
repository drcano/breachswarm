# Blue-team detection scorecard — OWASP Juice Shop (own instance) — emulation dry-run

Target: `http://172.17.0.2:3000` · actions: 7 · destructive blocked: 0 · audit: VERIFIED

| ATT&CK | Technique | Control tested | Attempts | Blocked | **Missed** | Verdict |
|---|---|---|---|---|---|---|
| T1190 | SQL injection | WAF/IDS | 3 | 0 | 3 | 🔴 DETECTION GAP |
| T1213 | IDOR / BOLA object access | DLP/authz | 1 | 0 | 1 | 🔴 DETECTION GAP |

**2 control gap(s)** across 2 techniques exercised.