# RAG ablation — does the knowledge base actually help solve?

The overnight A/B could only say the RAG was *consistent with* fast solves, not that it
*caused* them (recon-playbook and the base model are confounds). This isolates it: same
target (Gauntlet, 5-stage), same baseline agent, N=2, toggling the two RAG mechanisms via
`CTF_KB` (the `search_knowledge` tool) and `CTF_PLAYBOOK` (recon→card auto-load).

| condition | solved | wall med | turns med | note |
|---|---|---|---|---|
| full (RAG + recon-playbook) | 2/2 | 160s | 38 | default |
| no-playbook (KB tool only) | 2/2 | 186s | 46 | |
| **no-RAG (neither)** | **2/2** | **144s** | 40 | fastest by median |

## Finding (honest, and a little humbling)
**On Gauntlet, the RAG shows no measurable benefit** — solve rate, wall-clock and turns are
all within N=2 noise, and the *no-RAG* condition was marginally fastest. The reason is
straightforward: Gauntlet's stages (IDOR, NoSQLi `$ne`, JWT `alg:none`, decimal-IP SSRF,
command injection) are techniques the base model already knows cold, so a retrieved playbook
is redundant. The earlier "deeper-chain-solved-faster" effect is about **per-stage technique
familiarity**, not RAG presence.

## What this does and doesn't say
- **Does say:** the RAG is not a universal accelerant. On chains built from common,
  well-known techniques it earns nothing on speed or solve rate (it stays cheap/harmless —
  retrieval is stdlib TF-IDF, pulled on demand — but "cheap and harmless" ≠ "helps here").
- **Doesn't say the RAG is useless:** its plausible value is on techniques the base model
  is *shaky* on — exact WAF-evasion syntax, rarer crypto/pwn recipes, precise payloads —
  none of which Gauntlet exercises. That's the untested hypothesis.
- **Caveat:** N=2, one easy target, high variance. This refutes "RAG helps *here*," not
  "RAG helps *somewhere*."

## Next test (to actually find where RAG pays)
Ablate on a target whose winning move is a **precise, less-common payload** the base model
tends to fumble — e.g. Fortress S1 (`UNION/**/SELECT` WAF evasion + `information_schema`
enumeration), or a crypto/pwn challenge. If RAG closes a gap there, that's its real niche;
if not, it's decoration and should be defended only on measured recall, not solve lift.

Evidence: `results/rag_full.jsonl`, `results/rag_noplaybook.jsonl`, `results/rag_norag.jsonl`.
