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
    r"|-X\s*DELETE\b|\b(?:method|action)['\"]?\s*[:=]\s*['\"]?(?:delete|remove|destroy|deactivate|purge)"
    # GET/POST action-endpoint deletion — the word is in the URL PATH, no -X DELETE (e.g. PortSwigger
    # /admin/delete?username=carlos, /delete-account?id=, /user/remove?uid=). The dominant real-world
    # destructive pattern the -X DELETE / SQL rules miss. ponytail: camelCase /deleteUser still slips.
    r"|/(?:delete|remove|destroy|deactivate|purge|wipe|unpublish)(?:[-_]\w+)?(?=[/?\s'\"]|$)"
    # destructive METHOD call inside an exploit payload (SSTI/deser/RCE) — e.g. a Twig payload that
    # invokes user.gdprDelete(). The HTTP-shaped rules above can't see intent inside a code payload.
    r"|\.\s*(?:delete|destroy|deactivate|gdprdelete)\w*\s*\("
    r"|\bformat\s+[a-z]:|\brmdir\s+/s", re.I)


def is_destructive(command: str) -> bool:
    return bool(_DESTRUCTIVE.search(command or ""))


# Self-cleanup: the agent creates test objects (folders, api_keys, bundles) on its OWN authorized
# trial site and should be able to remove them, but a blanket "allow DELETE" would reopen the rail
# that once let an agent delete an account overnight. So we allow a DELETE only when it targets an
# id/path THIS session created (captured from CREATE responses). ponytail: id/path capture only;
# an object referenced solely by an opaque name we never saw created stays blocked.
_CREATE_REF_RE = re.compile(r'"(?:id|path)"\s*:\s*"?([A-Za-z0-9_./-]{3,128})"?')


def is_http_create(command: str) -> bool:
    """A curl that CREATES a resource (POST/PUT, or a body with no read/delete verb)."""
    c = (command or "").lower()
    if re.search(r'-x\s*(get|delete|head)\b', c):
        return False
    return bool(re.search(r'-x\s*(post|put)\b', c)
                or re.search(r'(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode)?)\b', c))


def refs_in_response(text: str) -> set:
    """The object ids/paths a CREATE response returned — candidates for later self-cleanup."""
    return set(_CREATE_REF_RE.findall(text or ""))


def own_artifact_delete(command: str, own_refs) -> bool:
    """True iff command is an HTTP DELETE targeting an id/path in own_refs (self-created this
    session). Boundary-matched so '5554223' does not match '55542234'."""
    c = command or ""
    is_del = bool(re.search(r'-X\s*DELETE\b', c, re.I)
                  or re.search(r"method['\"]?\s*[:=]\s*['\"]?delete", c, re.I))
    if not (is_del and own_refs):
        return False
    return any(re.search(r'(?<![A-Za-z0-9_-])' + re.escape(r) + r'(?![A-Za-z0-9_-])', c)
               for r in own_refs)


def guard_destructive(command: str, destructive_allowed: bool, own_refs=None) -> tuple[bool, str]:
    """(allowed, reason). Blocks a destructive command unless the RoE authorizes destruction, or
    it's an HTTP DELETE of a test artifact THIS session created (own_refs)."""
    if destructive_allowed or not is_destructive(command):
        return True, "ok"
    if own_artifact_delete(command, own_refs):
        return True, "ok (self-created test-artifact cleanup)"
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
    # GET/POST action-endpoint deletion (the PortSwigger-lab gap: guard let /admin/delete?username=
    # through because there's no -X DELETE — the pipeline actually deleted carlos, destructive_blocks=0)
    assert is_destructive("curl 'http://t/admin/delete?username=carlos'")       # GET action delete
    assert is_destructive("curl -X POST http://t/admin/delete -d username=carlos")
    assert is_destructive("curl 'http://t/user/remove?uid=5'")
    assert is_destructive("curl 'http://t/delete-account?id=9'")
    assert is_destructive("curl -d 'action=delete&id=5' http://t/admin")
    assert not is_destructive("curl 'http://t/api/deleted-items'")              # a LISTING, not an action
    assert not is_destructive("curl 'http://t/search?q=delete'")                # 'delete' only in a query value
    # destructive METHOD call in a code-exec payload (SSTI-custom lab: Twig user.gdprDelete())
    assert is_destructive("curl -d 'blog-post-author-display=${user.gdprDelete()}' http://t/x")
    assert is_destructive("{{ session.user.delete() }}")
    assert not is_destructive("curl 'http://t/api/getDeletedItems'")            # read method, not .delete(
    assert guard_destructive("rm -rf /", False)[0] is False
    assert guard_destructive("rm -rf /", True)[0] is True            # RoE authorized destruction
    # self-cleanup: DELETE of a self-created artifact is allowed; anything else stays blocked
    refs = {"5554223", "pp/allowed"}
    assert guard_destructive("curl -X DELETE http://t/api/rest/v1/api_keys/5554223", False, refs)[0]
    assert guard_destructive("curl -X DELETE http://t/api/rest/v1/folders/pp/allowed", False, refs)[0]
    assert not guard_destructive("curl -X DELETE http://t/api/rest/v1/api_keys/9999999", False, refs)[0]
    assert not guard_destructive("curl -X DELETE http://t/api/rest/v1/api_keys/55542234", False, refs)[0]  # boundary
    assert not guard_destructive("rm -rf /home", False, {"/home"})[0]  # non-HTTP destruction never overridden
    assert not guard_destructive("curl -X DELETE http://t/api_keys/5554223", False, None)[0]  # nothing tracked
    assert is_http_create("curl -X POST -d '{\"name\":\"x\"}' http://t/folders")
    assert not is_http_create("curl -X DELETE http://t/folders/1")
    assert refs_in_response('{"id":5554223,"path":"pp/allowed"}') == {"5554223", "pp/allowed"}
    tok = canary_token("acme-exfil")
    assert is_canary(tok) and is_canary(f"leaked: {tok} found in paste")
    assert not is_canary("just some text")
    assert "START" in announce(None, "start", "engagement ACME-RT-2026-014")
    print("safety.py ok —", tok)


if __name__ == "__main__":
    demo()
