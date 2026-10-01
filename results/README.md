# Benchmark Evidence

Raw run outputs (JSONL, one result per line). Each row: task name, specialist,
`solved`, `near_miss`, extracted `flag`, `turns`, `duration_s`, `time_to_flag_s`,
and paths to that run's `writeup.md` + ground-truth `audit.jsonl`.

| File | What it is | Headline |
|---|---|---|
| `intercode100.jsonl` | **Full InterCode-CTF, all 100 tasks, pass@1** | **70/100 (70%)** +6 near |
| `owasp.jsonl` | OWASP Web Top 10 targets | 7/7 |
| `hard.jsonl` | Multi-step chains (mass-assign→admin, IDOR-after-auth, business-logic, filter-evasion SQLi) | 4/4 |
| `modern.jsonl` | Modern API classes (GraphQL, NoSQLi, XXE) | 3/3 |
| `crypto.jsonl` `forensics.jsonl` `rev.jsonl` `misc.jsonl` | Per-category InterCode runs | see README |
| `llm.jsonl` | OWASP LLM Top 10 attempts | LLM01 exploited; see `docs/owasp_coverage.md` |
| `allstar.jsonl` | Balanced 38-task run (full toolset + retries) | 27/38 |

**pass@1** = one attempt per task, no retries — the honest, reproducible convention.

Reproduce the headline number:
```bash
CTF_SANDBOX=docker python run.py challenges/intercode --retries 0 -o results/intercode100.jsonl
```

Bug-bounty run economics live in `../bounty_metrics.jsonl`; findings reports in
`../docs/juiceshop_findings.md`.
