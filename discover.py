"""Target-triage engine — rank HackerOne programs by how HUNTABLE they are for an automated agent.

The #1 lesson from real-target testing: bug-hunting is a volume+freshness game, and we were aiming
at the two most-hardened programs on the platform. This pulls the full program list and ranks each
by the criteria that actually matter for an autonomous, authorized agent:

  + permits automated/agent testing (the hard gate — most programs forbid it)
  + offers bounties
  + has an owned-instance path (trial / self-signup / demo) so we can run hard on our own data
  - anti-automation language (disqualifies)

Output is a ranked hunt QUEUE, not a single pick. Auth: HTTP Basic (H1_API_USER:H1_API_TOKEN from
env — never hard-coded). ponytail: keyword scoring is a first filter; read the finalists' policies
before running (score_program returns the matched quotes so a human can eyeball).
"""
from __future__ import annotations

import base64
import json
import os
import re
import urllib.request

_AUTO_YES = re.compile(
    r"automated testing|you may use automated|automation is (allowed|permitted|fine)|"
    r"\bai agent|ai-based|ai provider|any reasonable ai|automated tools (are|may)|"
    r"scanners? (are|is) (allowed|permitted)|automated scanning is (allowed|permitted)|"
    r"non-destructive automated|throttl", re.I)
_AUTO_NO = re.compile(
    r"no automated|manual testing only|automated scanning (is |are )?(not|pro)|"
    r"do not (use |run )?automat|automated (tools|scanning) (are |is )?(not|pro)|burp intruder|"
    r"no scanners|scanning is not allowed|automated attacks|prohibit\w*\s+\w*\s*automat", re.I)
_OWNED = re.compile(
    r"free trial|start a trial|self.?sign.?up|self.?service|create (a|an|your own) (trial |demo |test )?account|"
    r"demo account|virtual account|sandbox account|register (a|an|your) (trial|account)|test site", re.I)


def score_program(attrs: dict) -> dict:
    """Score one program's attributes. Returns {handle, score, bounties, automation, owned, why[]}.
    Negative automation is a hard disqualify (score = -1)."""
    pol = attrs.get("policy", "") or ""
    handle = attrs.get("handle", "")
    bounties = attrs.get("offers_bounties")
    yes, no = _AUTO_YES.search(pol), _AUTO_NO.search(pol)
    owned = _OWNED.search(pol)
    why = []
    if no:
        return {"handle": handle, "score": -1, "bounties": bounties, "automation": "FORBIDDEN",
                "owned": bool(owned), "why": [f"anti-automation: '{no.group(0)[:40]}'"]}
    score = 0
    automation = "silent"
    if yes:
        score += 4; automation = "permitted"; why.append(f"automation: '{yes.group(0)[:40]}'")
    if owned:
        score += 3; why.append(f"owned-instance: '{owned.group(0)[:40]}'")
    if bounties is True:
        score += 2; why.append("offers bounties")
    return {"handle": handle, "score": score, "bounties": bounties, "automation": automation,
            "owned": bool(owned), "why": why}


def rank_programs(programs: list) -> list:
    """Score + rank open programs. programs = list of API 'data' rows (with .attributes)."""
    scored = []
    for p in programs:
        a = p.get("attributes", {})
        if a.get("submission_state") != "open" or not a.get("policy"):
            continue
        s = score_program(a)
        if s["score"] > 0:
            scored.append(s)
    scored.sort(key=lambda s: (s["score"], s["owned"], s["bounties"] is True), reverse=True)
    return scored


_BASELINE = "results/scope_baseline.json"


def take_snapshot(programs: list, scopes_by_handle: dict) -> dict:
    """Build {handle: sorted[in-scope asset identifiers]} — the state we diff for freshness."""
    snap = {}
    for p in programs:
        h = p.get("attributes", {}).get("handle")
        if h:
            snap[h] = sorted(scopes_by_handle.get(h, []))
    return snap


def diff_snapshot(old: dict, new: dict) -> dict:
    """Pure diff → the HUNT TRIGGERS. First-mover on a new program/asset is where our speed wins.
    Returns {new_programs:[...], new_assets:{handle:[added...]}}."""
    new_programs = sorted(set(new) - set(old))
    new_assets = {}
    for h, assets in new.items():
        if h in old:
            added = sorted(set(assets) - set(old[h]))
            if added:
                new_assets[h] = added
    return {"new_programs": new_programs, "new_assets": new_assets}


def _scopes_for(user: str, tok: str, handle: str) -> list:
    auth = base64.b64encode(f"{user}:{tok}".encode()).decode()
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes?page%5Bsize%5D=100"
    try:
        req = urllib.request.Request(url, headers={"Authorization": "Basic " + auth,
                                                   "Accept": "application/json"})
        rows = json.load(urllib.request.urlopen(req, timeout=25)).get("data", [])
        return [r["attributes"].get("asset_identifier") for r in rows
                if r["attributes"].get("eligible_for_submission")]
    except Exception:
        return []


def watch(top_n: int = 25) -> None:
    """Freshness check: diff the current program list + top-ranked programs' scopes against the saved
    baseline; print NEW programs / NEW assets (the hunt triggers); update the baseline."""
    from pathlib import Path
    user, tok = os.getenv("H1_API_USER"), os.getenv("H1_API_TOKEN")
    if not (user and tok):
        raise SystemExit("set H1_API_USER and H1_API_TOKEN")
    progs = _fetch_all(user, tok)
    ranked = rank_programs(progs)
    watch_handles = [s["handle"] for s in ranked[:top_n]]      # only pull scopes for the hunt queue
    scopes = {h: _scopes_for(user, tok, h) for h in watch_handles}
    new = take_snapshot(progs, scopes)
    p = Path(_BASELINE)
    old = json.loads(p.read_text()) if p.exists() else {}
    d = diff_snapshot(old, new)
    if not old:
        print(f"[freshness] baseline created ({len(new)} programs). Re-run to detect changes.")
    elif d["new_programs"] or d["new_assets"]:
        print("🔥 FRESH SCOPE — hunt these FIRST (first-mover edge):")
        for h in d["new_programs"]:
            print(f"  NEW PROGRAM: {h}")
        for h, assets in d["new_assets"].items():
            print(f"  NEW ASSETS on {h}: {', '.join(assets)}")
    else:
        print("[freshness] no new programs/assets since last check.")
    # merge (keep scopes we didn't re-pull this run) and persist
    merged = {**old, **new}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(merged, indent=0))


def _fetch_all(user: str, tok: str) -> list:
    auth = base64.b64encode(f"{user}:{tok}".encode()).decode()
    def get(url):
        req = urllib.request.Request(url, headers={"Authorization": "Basic " + auth,
                                                   "Accept": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=30))
    progs, url = [], "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=100"
    while url and len(progs) < 800:
        d = get(url); progs += d.get("data", []); url = d.get("links", {}).get("next")
    return progs


def main():
    user, tok = os.getenv("H1_API_USER"), os.getenv("H1_API_TOKEN")
    if not (user and tok):
        raise SystemExit("set H1_API_USER and H1_API_TOKEN env vars (HackerOne API creds)")
    progs = _fetch_all(user, tok)
    ranked = rank_programs(progs)
    print(f"# Hunt queue — {len(ranked)} automation-friendly programs (of {len(progs)} total)\n")
    print(f"{'HANDLE':26} {'SCORE':>5} {'AUTO':10} {'OWNED':6} BOUNTIES  WHY")
    for s in ranked[:40]:
        print(f"{s['handle']:26} {s['score']:>5} {s['automation']:10} "
              f"{str(s['owned']):6} {str(s['bounties']):8}  {'; '.join(s['why'])[:70]}")


def demo() -> None:
    yes = {"handle": "good", "offers_bounties": True, "submission_state": "open",
           "policy": "You may use automated testing. Start a free trial to create a demo account."}
    no = {"handle": "bad", "offers_bounties": True, "submission_state": "open",
          "policy": "Automated scanning is prohibited. Manual testing only, no Burp Intruder."}
    meh = {"handle": "meh", "offers_bounties": False, "submission_state": "open",
           "policy": "Please report vulnerabilities responsibly."}
    g = score_program(yes)
    assert g["score"] == 9 and g["automation"] == "permitted" and g["owned"], g   # 4+3+2
    assert score_program(no)["score"] == -1 and score_program(no)["automation"] == "FORBIDDEN"
    assert score_program(meh)["score"] == 0
    ranked = rank_programs([{"attributes": yes}, {"attributes": no}, {"attributes": meh}])
    assert [r["handle"] for r in ranked] == ["good"], ranked   # only the huntable one, no/meh dropped
    # freshness diff — the hunt triggers
    old = {"a": ["x.com"], "b": ["y.com"]}
    new = {"a": ["x.com", "admin.x.com"], "b": ["y.com"], "c": ["z.com"]}
    d = diff_snapshot(old, new)
    assert d["new_programs"] == ["c"] and d["new_assets"] == {"a": ["admin.x.com"]}, d
    assert diff_snapshot(new, new) == {"new_programs": [], "new_assets": {}}   # no change
    snap = take_snapshot([{"attributes": {"handle": "p"}}], {"p": ["b.com", "a.com"]})
    assert snap == {"p": ["a.com", "b.com"]}                    # sorted
    print("discover.py ok")


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "rank"
    {"demo": demo, "-t": demo, "watch": watch, "rank": main}.get(cmd, main)()
