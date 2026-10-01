# Demo — What to Show in 90 Seconds

A reviewer will not clone and run this. Record one short screen capture and put
the GIF at the top of the README. Here's the exact shot list and the commands.

## The 90-second cut (storyboard)

| Time | Shot | Command / action |
|---|---|---|
| 0:00–0:10 | **The console.** Matrix-themed web UI, clean and modern. | `python server.py` → open `http://localhost:8000` |
| 0:10–0:35 | **Live exploit.** Launch a run against a live vulnerable service; show recon → specialist → tool calls streaming in real time. | Click a target in the console, or `./demo_live.sh sqli` |
| 0:35–0:55 | **The flag + writeup.** Verifier auto-stops on the flag; the LLM writeup appears explaining each step. | (auto) → open the generated `writeup.md` |
| 0:55–1:15 | **The report.** Switch to a bounty run; show the HackerOne-format findings report with CVSS/CWE. | open `docs/juiceshop_findings.md` |
| 1:15–1:30 | **The dashboard.** Metrics: solve rate, time-to-exploit histogram, cost. | open `http://localhost:8000/dashboard` |

The story the cut tells: *unknown target → autonomous exploit → client-ready
report → measured results.* That is the FDE loop in 90 seconds.

## One-command reproductions (for the README "Try it" section)

```bash
# Live web exploit against a fresh vulnerable service (no static files)
./demo_live.sh sqli

# Modern API vuln classes: GraphQL / NoSQLi / XXE
./modern_bench.sh

# OWASP Web Top 10 (7/7)
./owasp_bench.sh

# Full authorized bug-bounty run against your own Juice Shop (enforced egress)
python bounty.py --scope scope.juice.json --target http://<instance>:3000 --enforce
```

## Recording tips

- `terminalizer` or `asciinema` for the terminal shots; QuickTime/Kap for the GUI.
- Export to GIF at ≤ 8 MB so GitHub renders it inline.
- No audio needed — captions on the storyboard beats above.

## Already-live visual

`docs/how-it-works.html` is a self-contained visual walkthrough of the
architecture (published artifact) — link it in the README as the "how it works"
companion to the demo GIF.
