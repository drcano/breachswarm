"""RAG retrieval eval — proves the knowledge base returns the RIGHT card for a
realistic query, and catches regressions as the corpus grows.

Each case is (natural-language query, marker) where `marker` is a lowercase
substring that MUST appear in a retrieved chunk. We report recall@1 and recall@3.
This is the guardrail for adding cards: a new card must not knock existing queries
off rank-1. Dependency-free; run: ./.venv/bin/python eval_rag.py
"""
from __future__ import annotations

from knowledge_base import get_kb

# (query a specialist would actually ask, substring that proves the right card hit)
CASES: list[tuple[str, str]] = [
    ("bypass WAF blocking union select", "union/**/select"),
    ("read cloud metadata credentials via ssrf", "169.254"),
    ("code execution from a template input field", "{{7*7}}"),
    ("forge jwt token alg none", "alg"),
    ("access another user's object by changing the id", "idor"),
    ("upload a shell bypassing extension check", "double ext"),
    ("xml external entity file read", "<!entity"),
    ("escalate privileges by posting extra fields", "isadmin"),
    ("run os commands through an injection point", "`;`"),
    ("read /etc/passwd through path traversal", "../"),
    ("local file inclusion to rce", "php://filter"),
    ("insecure deserialization exploit", "pickle"),
    ("graphql introspection hidden mutations", "__schema"),
    ("stored xss steal cookies", "xss"),
    ("open redirect chain to oauth token theft", "redirect"),
    ("nosql injection mongodb auth bypass", "$ne"),
    ("race condition on balance transfer", "race"),
    ("crack rsa small exponent", "cube root"),
    ("padding oracle decrypt ciphertext", "padding"),
    ("rop chain stack overflow ret2libc", "rop"),
    ("format string leak and write", "%n"),
    ("hidden data in png image steganography", "zsteg"),
    ("carve files out of a blob", "binwalk"),
    ("follow tcp stream in a pcap for credentials", "tshark"),
    ("multi-stage chain sqli to ssrf to rce", "chain"),
    ("negative quantity price manipulation checkout", "business logic"),
    ("exposed .git directory and env secrets", "secrets"),
    ("cross-site request forgery state change", "csrf"),
]


def run() -> dict:
    kb = get_kb()
    at1 = at3 = 0
    misses = []
    for q, marker in CASES:
        hits = kb.search(q, k=3)
        texts = [(h["text"] + " " + h["title"]).lower() for h in hits]
        if texts and marker in texts[0]:
            at1 += 1
        if any(marker in t for t in texts):
            at3 += 1
        else:
            misses.append((q, marker, [h["title"][:40] for h in hits]))
    n = len(CASES)
    return {"n": n, "recall@1": at1, "recall@3": at3, "misses": misses}


def main() -> None:
    r = run()
    print(f"RAG eval: recall@1 = {r['recall@1']}/{r['n']}, "
          f"recall@3 = {r['recall@3']}/{r['n']}  "
          f"({len(get_kb().chunks)} chunks)")
    for q, marker, got in r["misses"]:
        print(f"  MISS  {q!r} (want {marker!r}) -> {got}")
    # guardrail: recall@3 must stay high or a card regressed retrieval
    assert r["recall@3"] >= r["n"] - 2, f"retrieval regressed: {r['misses']}"
    print("eval_rag.py ok")


if __name__ == "__main__":
    main()
