"""Flag detection — the auto-terminate core of the solver.

The flag format IS the verifier: if a specialist's output contains a string
matching the challenge's flag regex, the solve loop stops. No LLM needed for
the primary check.
"""
import re

# Common CTF flag shapes. A specific challenge overrides with its own regex.
DEFAULT_FLAG_RE = re.compile(r"(?:flag|ctf|pico|[A-Za-z0-9_]{2,10})\{[^}\n]{1,200}\}")


def find_flag(text: str, pattern: str | None = None) -> str | None:
    """Return the first flag-shaped substring in `text`, or None."""
    rx = re.compile(pattern) if pattern else DEFAULT_FLAG_RE
    m = rx.search(text or "")
    return m.group(0) if m else None


def is_correct(candidate: str | None, real_flag: str | None) -> bool:
    """Score a candidate. If the benchmark gives the real flag, compare exactly;
    otherwise a well-formed match is treated as a solve (live-CTF mode)."""
    if not candidate:
        return False
    if real_flag:
        return candidate.strip() == real_flag.strip()
    return True


def demo() -> None:
    assert find_flag("junk\nflag{h3llo_w0rld} more") == "flag{h3llo_w0rld}"
    assert find_flag("picoCTF{a_b_c}") == "picoCTF{a_b_c}"
    assert find_flag("no flag here") is None
    assert find_flag("KEY{xyz}", pattern=r"KEY\{[^}]+\}") == "KEY{xyz}"
    assert is_correct("flag{x}", "flag{x}") is True
    assert is_correct("flag{x}", "flag{y}") is False
    assert is_correct("flag{x}", None) is True          # live mode: shape is enough
    assert is_correct(None, None) is False
    print("flag.py ok")


if __name__ == "__main__":
    demo()
