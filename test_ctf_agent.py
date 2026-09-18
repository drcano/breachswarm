"""Fast, dependency-free unit checks for the pure-logic core (no Docker/LLM).
Run: ./.venv/bin/python test_ctf_agent.py
"""
from flag import find_flag, is_correct, is_near_miss, _is_placeholder
from recon import _classify
from specialists import route, SPECIALISTS
from solver import _is_unproductive, _stall_nudge, _decoy_nudge, _waf_nudge
from pricing import cost_of, summarize
from knowledge_base import KnowledgeBase
from audit_chain import AuditChain, verify as audit_verify
from engagement import Engagement


def test_flag_detection():
    assert find_flag("junk picoCTF{a_b_c} more") == "picoCTF{a_b_c}"
    assert find_flag("flag{h3llo}") == "flag{h3llo}"
    assert find_flag("nothing here") is None
    # custom pattern pins the format (stops rot13 look-alikes auto-terminating)
    assert find_flag("cvpbPGS{abg}", r"picoCTF\{[^}\s]+\}") is None
    assert find_flag("picoCTF{real}", r"picoCTF\{[^}\s]+\}") == "picoCTF{real}"
    # whitespace/backtick prose is not a flag
    assert find_flag("the flag is picoCTF{` at start `}") is None


def test_placeholder_rejection():
    assert _is_placeholder("picoCTF{...}")
    assert _is_placeholder("picoCTF{your_flag_here}")
    assert not _is_placeholder("picoCTF{r34l_0ne}")
    assert find_flag("submit picoCTF{...}") is None
    assert find_flag("picoCTF{r34l} vs picoCTF{...}") == "picoCTF{r34l}"


def test_scoring():
    assert is_correct("flag{x}", "flag{x}")
    assert not is_correct("flag{x}", "flag{y}")
    assert is_correct("flag{x}", None)          # live mode: shape is enough
    assert not is_correct(None, None)


def test_near_miss():
    # cracked but wrong case = near-miss, not a solve
    assert is_near_miss("PICOCTF{THENUMBERSMASON}", "picoCTF{thenumbersmason}")
    assert not is_near_miss("flag{x}", "flag{x}")
    assert not is_near_miss("picoCTF{wrong}", "picoCTF{right}")


def test_routing():
    cases = {
        "Cryptography": "crypto", "Reverse Engineering": "rev",
        "Binary Exploitation": "pwn", "Web Exploitation": "web",
        "Forensics": "forensics", "General Skills": "misc", None: "misc",
        "totally unknown": "misc",
    }
    for label, spec in cases.items():
        assert route(label) == spec, f"{label} -> {route(label)} != {spec}"
    for spec in cases.values():
        assert spec in SPECIALISTS


def test_knowledge_base():
    kb = KnowledgeBase()
    assert len(kb.chunks) >= 30, "expanded technique corpus not loaded"
    # natural-language queries must retrieve the right technique card at rank 1
    assert "union/**/select" in kb.search("bypass WAF union select", 1)[0]["text"].lower()
    # "cloud metadata via ssrf" disambiguated from LFI file-read (both read cloud creds)
    assert "169.254" in kb.search("ssrf fetch cloud metadata endpoint", 1)[0]["text"]
    assert "{{7*7}}" in kb.search("code execution from a template field", 1)[0]["text"]
    # expanded classes retrieve their card (regression guard for the big corpus)
    assert "pickle" in kb.search("insecure deserialization rce", 1)[0]["text"].lower()
    assert "$ne" in kb.search("nosql mongodb auth bypass operator", 1)[0]["text"].lower()
    assert "cube root" in kb.search("rsa small exponent e=3", 1)[0]["text"].lower()
    assert "chain" in kb.search("combine primitives multi-stage escalation", 1)[0]["text"].lower()


def test_pricing():
    assert cost_of("claude-opus-4-8", 1_000_000, 1_000_000) == 90.0   # 15 + 75
    assert cost_of("claude-sonnet-5", 1_000_000, 0) == 3.0
    s = summarize([{"m": {"inputTokens": 2_000_000, "outputTokens": 0,
                          "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0,
                          "costUSD": 6.0, "canonicalModel": "claude-sonnet-5"}}])
    assert s["cost_recomputed_usd"] == 6.0 and s["tokens"]["input"] == 2_000_000


def test_dead_end_detector():
    # failure-dominated / empty outputs are unproductive; flags & 200s are not
    assert _is_unproductive("401 Unauthorized\n403 Forbidden") is True
    assert _is_unproductive("") is True
    assert _is_unproductive("HTTP/1.1 200 OK\n{\"data\":{...}}") is False
    assert _is_unproductive("flag{win} 404 not found") is False   # flag wins
    # density over a sliding window: ~4 dead-ends among the last 6 fires, even when
    # a good result is interspersed (the pattern that dodged a consecutive counter)
    fails, ok = "401 403 refused not found", "HTTP/1.1 200 OK\n{\"data\":1}"
    st = {"window": [], "cooldown": 0}
    seq = [fails, fails, ok, fails, fails]   # 4 of 5 are dead-ends, not consecutive
    notes = [_stall_nudge(x, st) for x in seq]
    assert notes[:4] == ["", "", "", ""] and "dead-end detector" in notes[4]
    # cooldown: quiet immediately after firing even if still dense
    assert _stall_nudge(fails, st) == ""


def test_decoy_nudge():
    # a decoy flag in tool output triggers explicit feedback so the agent stops re-fetching
    n = _decoy_nudge('{"flag": "flag{debug_endpoint_not_the_real_flag}"}')
    assert "decoy detected" in n and "re-fetch" in n
    # a real flag in output produces no nudge (must not warn on genuine finds)
    assert _decoy_nudge("flag{f0rtr3ss_ch41n_5sti_after_ssrf_pwn}") == ""
    assert _decoy_nudge("HTTP/1.1 200 OK\n{\"data\":1}") == ""


def test_waf_nudge():
    st = {}
    n = _waf_nudge('{"error":"WAF: request blocked (suspicious input)"}', st)
    assert "evade" in n.lower() and "union/**/select" in n.lower()
    assert _waf_nudge("still blocked (suspicious input)", st) == ""   # one-shot per run
    assert _waf_nudge("HTTP/1.1 200 OK", {}) == ""                    # clean response, no fire
    assert _waf_nudge("here is the flag{real_one}", {}) == ""         # never on a flag


def test_audit_chain():
    import tempfile, os
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    a = AuditChain(p)
    a.record("technique", attack_id="T1190", evaded=True)
    a.record("finding", title="waf bypass", severity="high")
    assert audit_verify(p)[0] is True
    # tamper detection: edit a committed entry
    lines = open(p).read().splitlines()
    lines[0] = lines[0].replace("T1190", "T1486")
    open(p, "w").write("\n".join(lines) + "\n")
    assert audit_verify(p)[0] is False


def test_engagement():
    import tempfile, os, json, time
    d = tempfile.mkdtemp()
    f = os.path.join(d, "e.json")
    base = {"program": "t", "authorized": True, "in_scope": ["*.acme.test"],
            "allowed_techniques": ["T1190"], "loudness_budget_per_hour": 2}
    json.dump(dict(base, expires=time.time() + 3600), open(f, "w"))
    e = Engagement.load(f)
    assert e.allows_target("https://x.acme.test")[0] is True
    assert e.allows_target("https://evil.other")[0] is False
    assert e.technique_allowed("T1190") and not e.technique_allowed("T1486")
    assert e.spend() and e.spend() and not e.spend()          # budget cap
    # mandatory expiry
    json.dump(base, open(f, "w"))
    try:
        Engagement.load(f); assert False
    except ValueError:
        pass


def test_recon_classify():
    assert _classify("go pwn http://h/", "", "") == "web"
    assert _classify("", "x: ELF 64-bit LSB executable", "") == "rev"
    assert _classify("", "d.pcap: pcap capture file", "") == "forensics"
    assert _classify("", "p.png: PNG image data", "") == "forensics"
    assert _classify("", "k: data", "-----BEGIN RSA PRIVATE KEY-----") == "crypto"
    assert _classify("a riddle", "n.txt: ASCII text", "hello") == "misc"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t(); print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} test groups passed")
