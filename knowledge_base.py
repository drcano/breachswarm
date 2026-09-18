"""Retrieval knowledge base — RAG, not fine-tuning.

The system can't be "trained" (it's Claude via the SDK), and stuffing every technique
into the prompt bloats it (measured: the web specialist hit 5100 chars). Instead, a
searchable corpus the agent queries ON DEMAND: it pulls the one relevant technique
when it needs it, so the KB scales to any size without touching the prompt.

Retriever is stdlib TF-IDF (no vector DB, no embeddings API) — right-sized for
keyword-heavy security queries ("ssrf metadata bypass", "jwt alg none"). Corpus =
markdown under knowledge/ + curated docs; chunked by heading. Add data by dropping
more .md files in knowledge/ — no code change.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

# The corpus is the curated technique playbook only — dense, actionable cards under
# knowledge/. Project meta-docs (experiment logs, design notes) are deliberately NOT
# indexed: they pollute retrieval and outrank the payloads. Grow the KB by dropping
# more technique .md files in knowledge/ — no code change.
_SOURCES: list[str] = []
_DROP_DIR = "knowledge"

_WORD = re.compile(r"[a-z0-9]+")


def _tok(s: str) -> list[str]:
    return _WORD.findall(s.lower())


def _chunk_md(text: str, source: str) -> list[dict]:
    """Split a markdown doc into chunks at ## / ### headings."""
    chunks, title, buf = [], source, []
    for line in text.splitlines():
        if re.match(r"^#{2,3}\s", line):
            if buf:
                chunks.append({"title": title, "text": "\n".join(buf).strip(), "source": source})
            title = line.lstrip("# ").strip()
            buf = [line]
        else:
            buf.append(line)
    if buf:
        chunks.append({"title": title, "text": "\n".join(buf).strip(), "source": source})
    return [c for c in chunks if len(c["text"]) > 40]


class KnowledgeBase:
    def __init__(self, root: str = "."):
        self.root = Path(root)
        self.chunks: list[dict] = []
        self._load()
        self._index()

    def _load(self):
        paths = [self.root / s for s in _SOURCES]
        drop = self.root / _DROP_DIR
        if drop.is_dir():
            paths += sorted(drop.glob("**/*.md"))
        for p in paths:
            if p.is_file():
                self.chunks += _chunk_md(p.read_text(errors="replace"), p.name)

    def _index(self):
        # TF per chunk + document frequency for IDF
        self._tf = [Counter(_tok(c["text"] + " " + c["title"])) for c in self.chunks]
        df = Counter()
        for tf in self._tf:
            df.update(tf.keys())
        n = max(len(self.chunks), 1)
        self._idf = {t: math.log(1 + n / (1 + d)) for t, d in df.items()}

    def search(self, query: str, k: int = 3) -> list[dict]:
        # NB: tried BM25 (k1=1.5,b=0.75) here — it REGRESSED retrieval on this corpus
        # (recall@1 lost the SSTI query: "code execution" saturated toward pwn cards,
        # swamping the decisive rare term "template"). TF-IDF with a heading boost wins
        # the head-to-head on eval_rag.py, so we keep it. See docs/OVERNIGHT.md.
        q = _tok(query)
        scored = []
        for c, tf in zip(self.chunks, self._tf):
            length = sum(tf.values()) or 1
            score = sum((tf[t] / length) * self._idf.get(t, 0) for t in q)
            # small boost when a query term is in the heading (title relevance)
            score += 0.5 * sum(self._idf.get(t, 0) for t in q if t in _tok(c["title"]))
            if score > 0:
                scored.append((score, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:k]]


_KB: KnowledgeBase | None = None


def get_kb() -> KnowledgeBase:
    global _KB
    if _KB is None:
        _KB = KnowledgeBase()
    return _KB


def demo() -> None:
    kb = KnowledgeBase()
    assert kb.chunks, "no chunks loaded — check _SOURCES paths"
    # security queries should retrieve the right technique chunk
    top = kb.search("ssrf cloud metadata credentials bypass", k=3)
    joined = " ".join(c["text"].lower() for c in top)
    assert "ssrf" in joined and ("169.254" in joined or "metadata" in joined), \
        f"SSRF query missed; got {[c['title'] for c in top]}"
    top = kb.search("jwt token forge alg none weak secret", k=3)
    assert "jwt" in " ".join(c["text"].lower() for c in top), "JWT query missed"
    print(f"knowledge_base.py ok — {len(kb.chunks)} chunks; "
          f"SSRF top: {kb.search('ssrf metadata', 1)[0]['title'][:50]!r}")


if __name__ == "__main__":
    demo()
