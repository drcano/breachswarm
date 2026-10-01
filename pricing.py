"""Token-based cost accounting.

What's ground truth here is the raw per-model TOKEN COUNTS from
`ResultMessage.model_usage` — those are exact and re-derivable. The dollar figure is
NOT: it's token counts × the RATES table below, and those rates are an editable
assumption I have not verified against current Anthropic pricing.

Honest status (measured): `cost_recomputed_usd` currently runs ~2× the SDK's own
`costUSD` on cache-heavy runs (e.g. Fortress: SDK $3.26 vs recomputed $8.93) — that
gap means the RATES here (opus base and/or cache-read pricing) are stale, NOT that
the SDK is wrong. So treat **the SDK `costUSD` / `cost_sdk_usd` as authoritative**
and the recomputed number as an uncalibrated cross-check until RATES are corrected.
We record both plus the exact token counts so nothing is taken on faith.

RATES are USD per 1,000,000 tokens; cache_read ≈ 0.1× input, cache_write ≈ 1.25×
input (standard structure). Calibrate them against a known billed run before quoting
the recomputed dollar figure as real cost.
"""
from __future__ import annotations

# per 1M tokens (USD). Keyed by canonicalModel substring. EDIT to match current rates.
RATES = {
    "opus":   {"in": 15.0, "out": 75.0, "cache_read": 1.5,  "cache_write": 18.75},
    "sonnet": {"in": 3.0,  "out": 15.0, "cache_read": 0.3,  "cache_write": 3.75},
    "haiku":  {"in": 1.0,  "out": 5.0,  "cache_read": 0.1,  "cache_write": 1.25},
}
_DEFAULT = RATES["sonnet"]  # unknown model → assume mid-tier, flagged in breakdown


def _rate_for(model: str) -> dict:
    m = (model or "").lower()
    for key, r in RATES.items():
        if key in m:
            return r
    return _DEFAULT


def cost_of(model: str, inp: int, out: int, cr: int = 0, cw: int = 0) -> float:
    r = _rate_for(model)
    return round((inp * r["in"] + out * r["out"] + cr * r["cache_read"]
                  + cw * r["cache_write"]) / 1_000_000, 6)


def summarize(model_usages: list[dict]) -> dict:
    """Aggregate a run's ResultMessage.model_usage dicts into total tokens, a
    recomputed cost (from RATES), and the SDK's own summed costUSD for cross-check."""
    tok = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    cost_recomputed, cost_sdk, per_model = 0.0, 0.0, {}
    for mu in model_usages:
        for model, u in (mu or {}).items():
            canon = u.get("canonicalModel", model)
            inp = u.get("inputTokens", 0); out = u.get("outputTokens", 0)
            cr = u.get("cacheReadInputTokens", 0); cw = u.get("cacheCreationInputTokens", 0)
            tok["input"] += inp; tok["output"] += out
            tok["cache_read"] += cr; tok["cache_write"] += cw
            c = cost_of(canon, inp, out, cr, cw)
            cost_recomputed += c
            cost_sdk += u.get("costUSD", 0) or 0
            pm = per_model.setdefault(canon, {"input": 0, "output": 0, "cost": 0.0,
                                              "known_rate": _rate_for(canon) is not _DEFAULT})
            pm["input"] += inp; pm["output"] += out; pm["cost"] = round(pm["cost"] + c, 6)
    return {"tokens": tok,
            "cost_recomputed_usd": round(cost_recomputed, 4),
            "cost_sdk_usd": round(cost_sdk, 4),
            "per_model": per_model}


def demo() -> None:
    # 1M input + 1M output on opus = $15 + $75 = $90
    assert cost_of("claude-opus-4-8", 1_000_000, 1_000_000) == 90.0
    assert cost_of("claude-sonnet-5", 1_000_000, 0) == 3.0
    assert cost_of("unknown-model", 1_000_000, 0) == 3.0  # falls back to sonnet
    s = summarize([{"claude-opus-4-8": {"inputTokens": 1_000_000, "outputTokens": 0,
                                        "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0,
                                        "costUSD": 15.0, "canonicalModel": "claude-opus-4-8"}}])
    assert s["cost_recomputed_usd"] == 15.0 and s["cost_sdk_usd"] == 15.0
    assert s["tokens"]["input"] == 1_000_000
    print("pricing.py ok")


if __name__ == "__main__":
    demo()
