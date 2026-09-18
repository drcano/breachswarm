"""Safety rails for authorized emulation: no-destruction guard, canary tokens, deconfliction.

- guard_destructive: refuse actions that would DESTROY data/systems unless the RoE explicitly
  authorizes it (`destructive: true`). Realistic access is the goal; wrecking the client's data
  is never it — you prove impact with a canary, not by dropping a table.
- canary tokens: plant/read a unique marker instead of exfiltrating real data — proves the
  access path (and, if the token later surfaces, proves exfil) with zero data at risk.
- deconfliction: announce run phases to a shared channel the blue-team white cell watches, so
  "was that us?" always has an answer, in real time.
"""
from __future__ import annotations

import re
import time
import uuid
from pathlib import Path

# Actions that DESTROY data or availability. Blocked unless the engagement is `destructive`.
_DESTRUCTIVE = re.compile(
    r"\bdrop\s+(table|database|schema)\b|\btruncate\s+table\b|\bdelete\s+from\b(?![^;]*\bwhere\b)"
    r"|\bupdate\s+\w+\s+set\b(?![^;]*\bwhere\b)"                # UPDATE/DELETE without WHERE = mass
    r"|\brm\s+-rf?\b|\bmkfs\b|\bdd\s+if=|\bshred\b|>\s*/dev/sd"
    r"|\bshutdown\b|\breboot\b|\bhalt\b|:\(\)\s*\{.*\};:"        # fork bomb
    r"|-X\s*DELETE\b|\bmethod['\"]?\s*[:=]\s*['\"]?delete"       # HTTP delete of a resource
    r"|\bformat\s+[a-z]:|\brmdir\s+/s", re.I)


def is_destructive(command: str) -> bool:
    return bool(_DESTRUCTIVE.search(command or ""))


def guard_destructive(command: str, destructive_allowed: bool) -> tuple[bool, str]:
    """(allowed, reason). Blocks a destructive command unless the RoE authorizes destruction."""
    if destructive_allowed or not is_destructive(command):
        return True, "ok"
    return False, ("[safety] BLOCKED destructive action (RoE destructive=false). Prove impact "
                   "with a read-only PoC or a canary token, not by destroying data. If the "
                   "engagement truly authorizes destruction, set destructive=true in the RoE.")


def canary_token(label: str = "ctf") -> str:
    """A unique, harmless marker to plant instead of touching real data. If it ever resurfaces
    (in a paste, a log, an exfil channel), it proves the path end-to-end — with nothing at risk."""
    return f"CANARY-{re.sub(r'[^a-zA-Z0-9]', '', label)[:16]}-{uuid.uuid4().hex[:12]}"


def is_canary(s: str) -> bool:
    return bool(re.search(r"CANARY-[a-zA-Z0-9]{1,16}-[0-9a-f]{12}", s or ""))


def announce(channel: str | None, phase: str, detail: str = "", meta: dict | None = None) -> str:
    """Emit a deconfliction notice (run start/stop, high-impact action) to the white cell.
    `channel` is EITHER a file path (append a line the SOC tails) OR an http(s) webhook URL
    (POST JSON — Slack/Teams/generic). Best-effort and non-blocking: a down channel never
    stops the run. Sends run metadata only (phase/program/operator/timing) — never target
    data. The operator configures their OWN channel in the RoE, so this is authorized ops
    comms, not exfil."""
    line = f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {phase.upper()} {detail}".rstrip()
    if not channel:
        return line
    try:
        if channel.startswith(("http://", "https://")):
            import json as _json, urllib.request as _u
            payload = {"text": line, "phase": phase, "detail": detail, **(meta or {})}
            req = _u.Request(channel, data=_json.dumps(payload).encode(),
                             headers={"Content-Type": "application/json"}, method="POST")
            _u.urlopen(req, timeout=5).read()
        else:
            with open(channel, "a") as f:
                f.write(line + "\n")
    except Exception:
        pass   # deconfliction is best-effort; never block the engagement on a down channel
    return line


def demo() -> None:
    assert is_destructive("curl 'http://t/?q=1;DROP TABLE users--'")
    assert is_destructive("rm -rf /var/www")
    assert is_destructive("curl -X DELETE http://t/api/orders/5")
    assert is_destructive("DELETE FROM users")                       # no WHERE = mass delete
    assert not is_destructive("DELETE FROM users WHERE id=999999")   # scoped, has WHERE
    assert not is_destructive("curl 'http://t/?q=1 UNION SELECT ...'")  # read-only injection
    assert guard_destructive("rm -rf /", False)[0] is False
    assert guard_destructive("rm -rf /", True)[0] is True            # RoE authorized destruction
    tok = canary_token("acme-exfil")
    assert is_canary(tok) and is_canary(f"leaked: {tok} found in paste")
    assert not is_canary("just some text")
    assert "START" in announce(None, "start", "engagement ACME-RT-2026-014")
    print("safety.py ok —", tok)


if __name__ == "__main__":
    demo()
