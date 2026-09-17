"""Web GUI backend — a thin async layer over the existing solver engine.

Endpoints:
  GET  /                     -> the dashboard (static/index.html)
  GET  /api/challenges       -> list challenges (name, category, has-result)
  POST /api/run              -> launch a run; streams progress over SSE
  GET  /api/events           -> SSE stream of {type, ...} run events
  GET  /api/challenge/{name} -> audit trail + writeup for one challenge
  GET  /api/results          -> latest run's results

Reuses run.load()/route() and solver.solve() — no logic duplicated. Run it:
  ./.venv/bin/uvicorn server:app --port 8000
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from run import load
from solver import solve, Result
from specialists import route

ROOT = Path(__file__).parent
CHALLENGES = ROOT / "challenges" / "intercode"
app = FastAPI(title="ctf-agent")

# ---- run state (single active run; a dashboard is one operator) ----
_events: asyncio.Queue = asyncio.Queue()
_results: list[dict] = []
_running = False


def _list_challenges() -> list[dict]:
    out = []
    for d in sorted(CHALLENGES.glob("*/challenge.json")):
        m = json.loads(d.read_text())
        cdir = d.parent
        out.append({
            "name": m.get("name", cdir.name),
            "category": m.get("category"),
            "specialist": route(m.get("category")),
            "has_writeup": (cdir / "writeup.md").exists(),
        })
    return out


@app.get("/", response_class=HTMLResponse)
async def index():
    return (ROOT / "static" / "index.html").read_text()


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return (ROOT / "static" / "dashboard.html").read_text()


@app.get("/api/challenges")
async def challenges():
    return _list_challenges()


@app.get("/api/metrics")
async def metrics():
    """Aggregate all benchmark results + bounty runs into dashboard stats."""
    rows = []
    for f in ROOT.glob("results.*.jsonl"):
        for line in f.read_text().splitlines():
            if line.strip():
                try:
                    r = json.loads(line); r["_src"] = f.name; rows.append(r)
                except Exception:
                    pass
    # de-dupe by (source, name) keeping the latest occurrence
    seen = {}
    for r in rows:
        seen[(r["_src"], r.get("name"))] = r
    rows = list(seen.values())

    by_cat = {}
    for r in rows:
        c = r.get("specialist") or "?"
        b = by_cat.setdefault(c, {"total": 0, "solved": 0, "durations": []})
        b["total"] += 1
        if r.get("solved"):
            b["solved"] += 1
            if r.get("time_to_flag_s"):
                b["durations"].append(r["time_to_flag_s"])

    solved = [r for r in rows if r.get("solved")]
    ttf = sorted(r["time_to_flag_s"] for r in solved if r.get("time_to_flag_s"))
    costs = [r["cost_usd"] for r in rows if r.get("cost_usd")]

    bounty = []
    bm = ROOT / "bounty_metrics.jsonl"
    if bm.exists():
        for line in bm.read_text().splitlines():
            if line.strip():
                try: bounty.append(json.loads(line))
                except Exception: pass

    return {
        "total": len(rows), "solved": len(solved),
        "solve_rate": round(len(solved) / len(rows), 3) if rows else 0,
        "by_category": {c: {"total": b["total"], "solved": b["solved"],
                            "rate": round(b["solved"] / b["total"], 3) if b["total"] else 0}
                        for c, b in sorted(by_cat.items())},
        "time_to_exploit": {
            "fastest": ttf[0] if ttf else None,
            "median": ttf[len(ttf) // 2] if ttf else None,
            "slowest": ttf[-1] if ttf else None,
            "samples": ttf,
        },
        "cost_total_usd": round(sum(costs), 2) if costs else 0,
        "bounty_runs": sorted(bounty, key=lambda r: r.get("time", 0), reverse=True)[:20],
    }


@app.get("/api/results")
async def results():
    return {"running": _running, "results": _results}


@app.get("/api/challenge/{name}")
async def challenge(name: str):
    # name is intercode_<id>; the dir is <id>
    cid = name.replace("intercode_", "")
    d = CHALLENGES / cid
    if not (d / "challenge.json").exists():
        return JSONResponse({"error": "not found"}, status_code=404)
    meta = json.loads((d / "challenge.json").read_text())
    audit = []
    if (d / "audit.jsonl").exists():
        audit = [json.loads(l) for l in (d / "audit.jsonl").read_text().splitlines() if l]
    writeup = (d / "writeup.md").read_text() if (d / "writeup.md").exists() else ""
    return {"name": name, "prompt": meta.get("prompt"), "category": meta.get("category"),
            "audit": audit, "writeup": writeup}


@app.post("/api/run")
async def run(cfg: dict):
    global _running, _results
    if _running:
        return JSONResponse({"error": "a run is already active"}, status_code=409)
    _results = []
    asyncio.create_task(_run_batch(cfg))
    return {"started": True}


async def _run_batch(cfg: dict):
    global _running
    _running = True
    category = cfg.get("category") or None
    limit = int(cfg.get("limit") or 10)
    backend = cfg.get("backend", "docker")
    max_turns = int(cfg.get("max_turns") or 15)
    concurrency = int(cfg.get("concurrency") or 4)
    retries = int(cfg.get("retries") or 0)
    import os
    os.environ["CTF_SANDBOX"] = backend

    dirs = []
    for d in sorted(CHALLENGES.glob("*/challenge.json")):
        spec = route(json.loads(d.read_text()).get("category"))
        if category and spec != category:
            continue
        dirs.append(d.parent)
        if len(dirs) >= limit:
            break

    await _events.put({"type": "start", "total": len(dirs), "config": cfg})
    sem = asyncio.Semaphore(concurrency)

    async def one(cdir):
        ch = load(cdir)
        await _events.put({"type": "solving", "name": ch.name})
        async with sem:
            try:
                r = await solve(ch, max_turns=max_turns, retries=retries)
            except Exception as e:
                r = Result(ch.name, route(ch.category), False, False, None, 0, None)
                await _events.put({"type": "error", "name": ch.name, "detail": str(e)[:200]})
        d = asdict(r)
        _results.append(d)
        await _events.put({"type": "result", **d})

    await asyncio.gather(*(one(c) for c in dirs))
    n = len(_results); s = sum(r["solved"] for r in _results)
    await _events.put({"type": "done", "solved": s, "total": n})
    globals()["_running"] = False


@app.get("/api/events")
async def events():
    async def gen():
        yield 'retry: 3000\n\n'
        while True:
            ev = await _events.get()
            yield f"data: {json.dumps(ev)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")
