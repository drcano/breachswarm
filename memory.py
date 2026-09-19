"""Cross-run memory — the system gets better with use instead of starting cold every time.
After a run we record, per target ARCHETYPE, what the operator had to establish (the scratchpad
fact keys) and whether it solved. Before a run on the same archetype we surface those as ADVISORY
priors: what to look for early — NOT specific values (a param name or encoding depth from one app
rarely transfers, so feeding values back would mislead). Full facts are kept in the ledger for
analysis; only the fact TYPES are fed forward, to prime recon without over-fitting.
ponytail: a jsonl ledger + a one-line digest, not a model. Archetype-scoped so priors stay relevant.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

LEDGER = Path("results/exploit_memory.jsonl")


def record(archetype: str, facts: dict, solved: bool, name: str = "",
           ledger: Path = LEDGER) -> None:
    if not archetype:
        return
    ledger.parent.mkdir(parents=True, exist_ok=True)
    row = {"ts": round(time.time()), "archetype": archetype, "solved": bool(solved),
           "fact_keys": sorted(facts or {}), "facts": facts or {}, "name": name}
    with open(ledger, "a") as f:
        f.write(json.dumps(row, default=str) + "\n")


def priors(archetype: str, ledger: Path = LEDGER) -> str:
    """Advisory recon prior for THIS archetype, from prior solved runs — fact TYPES to establish
    early, not values. Empty when we have no experience with this archetype yet."""
    if not archetype or not ledger.exists():
        return ""
    rows = [json.loads(l) for l in ledger.read_text().splitlines() if l.strip()]
    rows = [r for r in rows if r.get("archetype") == archetype and r.get("solved")]
    keys = Counter(k for r in rows for k in r.get("fact_keys", []))
    if not rows or not keys:
        return ""
    common = ", ".join(k for k, _ in keys.most_common(6))
    return (f"[priors — advisory, from {len(rows)} solved {archetype} engagement(s)] operators "
            f"here typically had to establish: {common}. Determine these early; do NOT assume "
            f"specific values (they rarely transfer between targets).")


def demo() -> None:
    import tempfile
    p = Path(tempfile.mkdtemp()) / "m.jsonl"
    for i in range(3):
        record("REST-JSON API", {"param": "q", "encode_depth": "3"}, True, f"r{i}", ledger=p)
    record("REST-JSON API", {"x": "y"}, False, "fail", ledger=p)   # unsolved: ignored by priors
    record("CMS", {"plugin": "z"}, True, "cms", ledger=p)
    s = priors("REST-JSON API", p)
    assert "3 solved" in s and "param" in s and "encode_depth" in s, s
    assert priors("GraphQL API", p) == ""       # no experience -> silent, no misleading
    print("memory.py ok")


if __name__ == "__main__":
    demo()
