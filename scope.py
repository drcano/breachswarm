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
# Loopback and link-local are CIDR ranges, not single IPs: 127.0.0.1 alone left
# the rest of 127/8 open, and 169.254.169.254 alone left the ECS-credential
# endpoint 169.254.170.2 (and the rest of link-local) reachable.
_ALWAYS_DENY = [
    "*.gov", "*.mil",
    "127.0.0.0/8", "::1", "0.0.0.0", "localhost",          # loopback / unspecified
    "169.254.0.0/16", "fd00:ec2::254",                     # link-local: AWS IMDS+ECS creds, IPv6 IMDS
    "metadata.google.internal", "metadata.goog",           # GCP metadata (NOT under *.google.com)
    "*.google.com", "*.amazonaws.com",
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
            net = ipaddress.ip_network(pattern, strict=False)
            ip = ipaddress.ip_address(host)
            mapped = getattr(ip, "ipv4_mapped", None)   # [::ffff:169.254.169.254] -> 169.254.169.254
            return ip in net or (mapped is not None and mapped in net)
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
    # A broad in_scope glob must NOT reopen loopback / link-local / GCP metadata.
    wide = Scope(program="t", authorized=True, in_scope=["*", "127.0.0.0/8", "169.254.0.0/16"])
    assert wide.allows("http://127.0.0.2/")[0] is False           # rest of 127/8, not just .1
    assert wide.allows("http://[::1]/")[0] is False               # IPv6 loopback
    assert wide.allows("http://169.254.170.2/")[0] is False       # AWS ECS credential endpoint
    assert wide.allows("http://metadata.google.internal/")[0] is False  # GCP metadata host
    assert wide.allows("http://[::ffff:169.254.169.254]/")[0] is False  # IPv4-mapped IMDS bypass
    assert wide.allows("http://app.corp.test/")[0] is True        # legit host still allowed
    # explicit operator override still works (rare; e.g. authorized localhost staging)
    assert Scope(program="t", authorized=True, in_scope=["127.0.0.0/8"],
                 allow_metadata_hosts=True).allows("http://127.0.0.1/")[0] is True
    print("scope.py ok")


if __name__ == "__main__":
    demo()
