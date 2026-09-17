"""Authorization + scope guardrail for real-world (bug-bounty / pentest) use.

Hard rule: the agent may only touch hosts the operator has EXPLICITLY authorized
and declared in-scope. Nothing runs against a real target without a scope file
that says `authorized: true` and lists the target. Out-of-scope hosts are refused.

This is the enforcement layer; `bounty.py` is the runner that uses it.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# Never allow testing infrastructure that isn't yours to test, even if a scope
# file lists it. These are common shared/critical hosts and metadata endpoints.
_ALWAYS_DENY = [
    "*.gov", "*.mil", "169.254.169.254",           # cloud metadata (SSRF magnet)
    "localhost", "127.0.0.1", "*.google.com", "*.amazonaws.com",
]


@dataclass
class Scope:
    program: str
    authorized: bool = False
    in_scope: list[str] = field(default_factory=list)      # host globs, e.g. *.example.com
    out_of_scope: list[str] = field(default_factory=list)
    rate_limit_rps: float = 1.0
    allow_metadata_hosts: bool = False   # explicit override for the deny-list (rare)
    notes: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        return cls(**json.loads(Path(path).read_text()))

    def _host(self, target: str) -> str:
        if "://" not in target:
            target = "http://" + target
        return (urlparse(target).hostname or "").lower()

    def allows(self, target: str) -> tuple[bool, str]:
        """(ok, reason). A target is allowed only if authorized, matches in_scope,
        matches no out_of_scope, and hits no always-deny rule."""
        if not self.authorized:
            return False, "scope not authorized (authorized != true)"
        host = self._host(target)
        if not host:
            return False, "no host in target"
        deny = self.out_of_scope + ([] if self.allow_metadata_hosts else _ALWAYS_DENY)
        for pat in deny:
            if _match(host, pat):
                return False, f"host {host} is out of scope ({pat})"
        for pat in self.in_scope:
            if _match(host, pat):
                return True, f"in scope ({pat})"
        return False, f"host {host} not in declared scope"


def _match(host: str, pattern: str) -> bool:
    # CIDR support (e.g. 10.0.0.0/8) plus hostname globs
    try:
        if "/" in pattern:
            return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        pass
    return fnmatch.fnmatch(host, pattern) or host == pattern


def demo() -> None:
    s = Scope(program="test", authorized=True, in_scope=["*.example.com"],
              out_of_scope=["admin.example.com"])
    assert s.allows("https://app.example.com/x")[0] is True
    assert s.allows("https://admin.example.com")[0] is False   # explicit OOS
    assert s.allows("https://evil.test")[0] is False           # not in scope
    assert s.allows("http://169.254.169.254/latest")[0] is False  # always-deny
    assert Scope(program="t", authorized=False, in_scope=["*"]).allows("http://x.com")[0] is False
    print("scope.py ok")


if __name__ == "__main__":
    demo()
