"""Rules-of-Engagement engine — `scope.py`, grown up for authorized adversary emulation.

Authorization is the only thing separating red-teaming from intrusion, so it's enforced in
code, not trusted to good intentions:
  - host allowlist + always-deny (delegated to Scope),
  - a REQUIRED expiry (no open-ended authorization) and optional start (a booked window),
  - an explicit technique allowlist (ATT&CK ids/classes; "*" = all authorized),
  - a loudness budget (max actions/hour) so "realistic" never means "reckless",
  - destructive actions OFF by default (use canaries, not real data),
  - an out-of-band kill switch the agent must honor.

Realism is fine — replicating a real actor is the point of the exercise. UNaccountable or
UNauthorized action is not. Pair this with `audit_chain.AuditChain` (the tamper-evident log)
so every action taken under this authorization is recorded for the client's debrief.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from scope import Scope

_SCOPE_KEYS = {"program", "authorized", "in_scope", "out_of_scope",
               "rate_limit_rps", "allow_metadata_hosts", "notes"}


def _ts(v) -> float | None:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()


@dataclass
class Engagement:
    scope: Scope
    expires: float                 # epoch; REQUIRED — authorization always ends
    starts: float | None
    allowed_techniques: list[str]  # ATT&CK ids/classes; ["*"] = all authorized; [] = none
    loudness_budget_per_hour: int
    destructive: bool
    kill_switch: str | None        # path; if it exists, the engagement is aborted
    operator: str
    deconfliction: str | None      # path to a shared white-cell channel for run notices
    _actions: list = field(default_factory=list)   # sliding-window action timestamps

    @classmethod
    def load(cls, path: str | Path) -> "Engagement":
        d = json.loads(Path(path).read_text())
        if not d.get("authorized"):
            raise ValueError("engagement not authorized (authorized != true)")
        exp = _ts(d.get("expires"))
        if exp is None:
            raise ValueError("engagement requires an 'expires' — no open-ended authorization")
        return cls(
            scope=Scope(**{k: v for k, v in d.items() if k in _SCOPE_KEYS}),
            expires=exp, starts=_ts(d.get("starts")),
            allowed_techniques=list(d.get("allowed_techniques", [])),
            loudness_budget_per_hour=int(d.get("loudness_budget_per_hour", 120)),
            destructive=bool(d.get("destructive", False)),
            kill_switch=d.get("kill_switch"), operator=d.get("operator", ""),
            deconfliction=d.get("deconfliction"))

    # --- authorization gates ---
    def killed(self) -> bool:
        return bool(self.kill_switch) and Path(self.kill_switch).exists()

    def active(self, now: float | None = None) -> tuple[bool, str]:
        now = now or time.time()
        if self.killed():
            return False, "kill switch engaged — aborting"
        if self.starts and now < self.starts:
            return False, "engagement window has not started"
        if now >= self.expires:
            return False, "engagement authorization has EXPIRED"
        return True, "active"

    def allows_target(self, url: str, now: float | None = None) -> tuple[bool, str]:
        ok, why = self.active(now)
        if not ok:
            return False, why
        return self.scope.allows(url)

    def technique_allowed(self, attack_id: str) -> bool:
        a = self.allowed_techniques
        return "*" in a or attack_id in a or any(attack_id.startswith(p) for p in a if p != "*")

    # --- loudness budget (max actions/hour) ---
    def can_act(self, now: float | None = None) -> bool:
        now = now or time.time()
        self._actions = [t for t in self._actions if now - t < 3600]
        return len(self._actions) < self.loudness_budget_per_hour

    def spend(self, now: float | None = None) -> bool:
        if not self.can_act(now):
            return False
        self._actions.append(now or time.time())
        return True

    def preflight(self) -> str:
        ok, why = self.active()
        if not ok:
            raise SystemExit(f"[engagement] REFUSED: {why}")
        exp = datetime.fromtimestamp(self.expires).isoformat(timespec="minutes")
        return (f"[engagement] {self.scope.program} — operator={self.operator}; "
                f"in_scope={self.scope.in_scope}; techniques={self.allowed_techniques}; "
                f"budget={self.loudness_budget_per_hour}/h; destructive={self.destructive}; "
                f"expires={exp}; kill_switch={self.kill_switch or 'none'}")


def demo() -> None:
    import tempfile
    base = {"program": "Acme purple-team", "authorized": True, "operator": "dante",
            "in_scope": ["*.acme.test"], "allowed_techniques": ["T1190", "T1059"],
            "loudness_budget_per_hour": 3, "destructive": False}
    d = Path(tempfile.mkdtemp())

    # expiry is mandatory
    (d / "noexp.json").write_text(json.dumps(base))
    try:
        Engagement.load(d / "noexp.json"); assert False, "should require expiry"
    except ValueError:
        pass

    # a live engagement
    ks = d / "STOP"
    live = dict(base, expires=time.time() + 3600, kill_switch=str(ks))
    (d / "live.json").write_text(json.dumps(live))
    e = Engagement.load(d / "live.json")
    assert e.active()[0]
    assert e.allows_target("https://app.acme.test")[0] is True
    assert e.allows_target("https://evil.other")[0] is False            # out of scope
    assert e.technique_allowed("T1190") and e.technique_allowed("T1059.001")  # prefix
    assert not e.technique_allowed("T1486")                             # ransomware: not allowed
    # loudness budget
    assert e.spend() and e.spend() and e.spend() and not e.spend()      # 3/h cap
    # expired engagement refuses everything
    exp = Engagement.load(d / "live.json"); exp.expires = time.time() - 1
    assert exp.active()[0] is False and exp.allows_target("https://app.acme.test")[0] is False
    # kill switch
    ks.write_text("stop")
    assert e.killed() and e.active()[0] is False
    print("engagement.py ok")


if __name__ == "__main__":
    demo()
