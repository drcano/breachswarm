"""Live self-check for the crypto_solve primitive (primitives.crypto_solve.run).

Runs the primitive's script on the HOST (stdlib only — no Docker, no network, no RsaCtfTool)
and asserts the three pure-python paths recover the plaintext:
  (a) RSA small-e: m=b'flag{rsa}', e=3, n a modulus with m^3 < n, c=m^3 % n  -> cube-root path.
  (b) single-byte XOR: b'flag{xor_me}' ^ 0x42, passed as hex          -> classical XOR brute.
  (c) hash: md5('sunshine'), 'sunshine' in a tiny wordlist file        -> hash wordlist crack.

Run: ./.venv/bin/python verify_crypto_solve.py
"""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from primitives import crypto_solve


class HostSB:
    """Minimal sandbox shim: run the primitive's script on the host (python3 + base64)."""
    def bash(self, cmd: str, timeout=None) -> str:
        return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                              timeout=120).stdout


if __name__ == "__main__":
    sb = HostSB()

    # (a) RSA small-e cube root
    m = int.from_bytes(b"flag{rsa}", "big")
    e = 3
    n = m ** 3 + 1                          # any n > m^e so c == m^e (no modular reduction)
    c = pow(m, e, n)
    out = crypto_solve.run(sb, {"n": str(n), "e": str(e), "c": str(c)})
    print(out.strip())
    assert "CRYPTO_SOLVE_OK rsa/small-e" in out, "cube-root path did not fire"
    assert "flag{rsa}" in out, f"RSA cube-root did not recover the plaintext:\n{out}"
    print("  ok  RSA small-e cube root recovered flag{rsa}")

    # (b) single-byte XOR (passed as hex so it survives as a string)
    ct = bytes(b ^ 0x42 for b in b"flag{xor_me}").hex()
    out = crypto_solve.run(sb, {"ciphertext": ct})
    print(out.strip())
    assert "CRYPTO_SOLVE_OK classical" in out, "classical path did not fire"
    assert "flag{xor_me}" in out, f"XOR brute did not recover the plaintext:\n{out}"
    print("  ok  single-byte XOR brute recovered flag{xor_me}")

    # (c) hash crack against a tiny wordlist (word NOT in the builtin list -> exercises the scan)
    wl = Path(tempfile.mkdtemp()) / "wl.txt"
    wl.write_text("wrong1\ncorrecthorse\nwrong2\n")
    h = hashlib.md5(b"correcthorse").hexdigest()
    out = crypto_solve.run(sb, {"hash": h, "wordlist": str(wl)})
    print(out.strip())
    assert "hash/md5 wordlist" in out, "hash wordlist path did not fire"
    assert "PLAINTEXT: correcthorse" in out, f"hash crack did not recover the plaintext:\n{out}"
    print("  ok  md5 cracked from the wordlist (correcthorse)")

    # arg guards
    assert "nothing to route on" in crypto_solve.run(sb, {})
    assert "must be a decimal integer" in crypto_solve.run(sb, {"n": "0xdead", "e": "3", "c": "5"})
    print("  ok  arg validation")

    print("\ncrypto_solve verified: one call solves RSA small-e, single-byte XOR, and a hash crack")
