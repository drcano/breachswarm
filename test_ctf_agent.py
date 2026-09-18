"""Fast, dependency-free unit checks for the pure-logic core (no Docker/LLM).
Run: ./.venv/bin/python test_ctf_agent.py
"""
from flag import find_flag, is_correct, is_near_miss, _is_placeholder
from recon import _classify
from specialists import route, SPECIALISTS
from solver import _is_unproductive, _stall_nudge


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
