"""Token-based cost accounting — self-verifiable, not SDK-trusted.

The SDK hands back a single opaque `total_cost_usd`. This instead reads the raw
per-model token counts from `ResultMessage.model_usage` (ground truth) and recomputes
cost from a VISIBLE rate table, so any figure we report can be re-derived from
tokens × rates rather than taken on faith. We also surface the SDK's own per-model
`costUSD` alongside, so a divergence between the two is a signal (e.g. stale rates).

RATES are USD per 1,000,000 tokens. VERIFY against current Anthropic pricing before
quoting the recomputed number as billed cost — token counts are exact, rates are the
editable assumption. cache_read ≈ 0.1× input, cache_write ≈ 1.25× input (standard
Anthropic cache pricing structure).
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
