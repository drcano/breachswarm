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
import re
import time
from collections import Counter
from pathlib import Path

LEDGER = Path("results/exploit_memory.jsonl")
CAMPAIGN = Path("results/campaign_memory.jsonl")
# Campaign memory keeps per-TARGET state across runs, WITH values (unlike archetype priors: on
# the SAME target a param name / endpoint / valid id still applies next run). But never persist
# secrets — tokens expire and don't belong on disk; the durable value is the structural facts.
_SECRETISH = re.compile(r"token|jwt|secret|passw|api[_-]?key|\bkey\b|cred|cookie|session|bearer", re.I)


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


def record_campaign(target: str, dump: dict, ledger: Path = CAMPAIGN) -> None:
    """Persist per-TARGET state (surfaces + non-secret facts) so a later run on the SAME target
    continues from what earlier runs established instead of starting cold."""
    from scratchpad import netloc_of
    net = netloc_of(target or "")
    facts = {k: v for k, v in (dump.get("facts") or {}).items() if not _SECRETISH.search(k)}
    surfaces = dump.get("surfaces") or {}
    leads = dump.get("leads") or []
    if not net or not (facts or surfaces or leads):
        return
    ledger.parent.mkdir(parents=True, exist_ok=True)
    row = {"ts": round(time.time()), "target": net, "facts": facts, "surfaces": surfaces,
           "leads": leads}
    with open(ledger, "a") as f:
        f.write(json.dumps(row, default=str) + "\n")


def campaign_recall(target: str, ledger: Path = CAMPAIGN) -> str:
    """Priming block from prior runs on THIS EXACT target — merged surfaces + facts (values kept,
    same target). Empty when this target has no history yet."""
    from scratchpad import Scratchpad, netloc_of
    net = netloc_of(target or "")
    if not net or not ledger.exists():
        return ""
    rows = [json.loads(l) for l in ledger.read_text().splitlines() if l.strip()]
    rows = [r for r in rows if r.get("target") == net]
    if not rows:
        return ""
    sp = Scratchpad()
    for r in rows:                       # later rows win on key collisions
        sp.surfaces.update(r.get("surfaces", {}))
        sp.facts.update(r.get("facts", {}))
        for l in r.get("leads", []):     # add_lead dedups on observation + caps the backlog
            sp.add_lead(l.get("observation", ""), l.get("why", ""), l.get("surface", ""))
    if not (sp.facts or sp.surfaces or sp.leads):
        return ""
    return (f"CAMPAIGN MEMORY — this EXACT target was assessed before across {len(rows)} run(s). "
            f"Reuse/confirm this instead of re-deriving (same target, values still apply):\n"
            + sp.summary())


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
    # campaign memory: per-target, values kept across runs, secrets dropped
    cp = Path(tempfile.mkdtemp()) / "c.jsonl"
    record_campaign("https://acme.example.com/app",
                    {"facts": {"param": "q", "admin_token": "ey.SECRET"}, "surfaces": {},
                     "leads": [{"observation": "search reflects input", "why": "XSS?"}]}, ledger=cp)
    record_campaign("acme.example.com", {"facts": {"valid_ids": "1-9"}, "surfaces": {}}, ledger=cp)
    r = campaign_recall("https://acme.example.com/other", ledger=cp)   # same host, diff path
    assert "param = q" in r and "valid_ids = 1-9" in r, r
    assert "admin_token" not in r and "SECRET" not in r, "secret leaked into campaign memory"
    assert "open leads" in r and "search reflects input" in r, r      # leads resume next run
    assert campaign_recall("other.example.com", ledger=cp) == ""       # different target -> silent
    print("memory.py ok")


if __name__ == "__main__":
    demo()
