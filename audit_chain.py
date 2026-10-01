"""Tamper-evident audit log — hash-chained, append-only JSONL.

The accountability spine for authorized adversary-emulation runs. The agent may evade the
TARGET's detective controls (that IS the test), but every action it takes is recorded here
in a hash chain that cannot be silently edited or truncated after the fact. This is the
inverse of anti-forensics: a stealth red-team agent produces MORE evidence than a normal
tool, for the client's after-action debrief — not less.

Each entry commits to the previous one: hash = sha256(prev_hash || canonical(entry)). Change
or drop any past entry and `verify()` fails at that seq. If this log could be disabled or
rewritten, the "authorized + fully documented" model collapses — so it's mandatory and
verifiable. (ponytail: SHA-256 chain, not a Merkle tree / signed log — upgrade to an HSM-
signed or external-timestamped chain if a run must be defensible against the operator too.)
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

GENESIS = "0" * 64


def _canon(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + _canon(body)).encode()).hexdigest()


class AuditChain:
    """Append-only, hash-chained audit writer. Resumes an existing chain on open."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev = self._resume()

    def _resume(self) -> tuple[int, str]:
        seq, prev = 0, GENESIS
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    e = json.loads(line)
                    seq, prev = e["seq"] + 1, e["hash"]
        return seq, prev

    def record(self, kind: str, **fields) -> dict:
        """Append one immutable event. `kind` is the event type (e.g. 'recon',
        'request', 'technique', 'finding', 'abort'); fields are the payload."""
        body = {"seq": self._seq, "ts": round(time.time(), 3), "kind": kind,
                "prev": self._prev, **fields}
        h = _hash(self._prev, body)
        body["hash"] = h
        with open(self.path, "a") as f:
            f.write(_canon(body) + "\n")
        self._seq, self._prev = self._seq + 1, h
        return body


def verify(path: str) -> tuple[bool, str]:
    """Re-walk the chain; return (ok, message). Detects edits, reorders, and truncation-
    in-the-middle (a broken prev link). Trailing truncation can't be caught by the chain
    alone — anchor the tip externally (print/commit it) if you need that guarantee."""
    prev, n = GENESIS, 0
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        claimed = e.pop("hash")
        if e.get("prev") != prev:
            return False, f"seq {e.get('seq')}: prev-link mismatch (reorder/insert/delete)"
        if _hash(prev, e) != claimed:
            return False, f"seq {e.get('seq')}: hash mismatch (entry was edited)"
        if e.get("seq") != n:
            return False, f"expected seq {n}, got {e.get('seq')}"
        prev, n = claimed, n + 1
    return True, f"chain valid: {n} entries, tip {prev[:12]}…"


def demo() -> None:
    import tempfile
    p = Path(tempfile.mkdtemp()) / "audit.jsonl"
    a = AuditChain(str(p))
    a.record("recon", target="http://lab", note="fingerprint")
    a.record("technique", attack_id="T1190", payload="UNION/**/SELECT", evaded=True)
    a.record("finding", title="WAF bypassable via inline comment", severity="high")
    ok, msg = verify(str(p))
    assert ok, msg
    # resume + tamper detection
    b = AuditChain(str(p)); b.record("abort", reason="kill-switch")
    ok, _ = verify(str(p)); assert ok
    lines = p.read_text().splitlines()
    i = next(k for k, l in enumerate(lines) if "high" in l)   # the finding entry
    lines[i] = lines[i].replace("high", "low")               # edit a past entry
    p.write_text("\n".join(lines) + "\n")
    ok, msg = verify(str(p))
    assert not ok and "edited" in msg, f"tamper not caught: {msg}"
    print("audit_chain.py ok —", msg)


if __name__ == "__main__":
    demo()
