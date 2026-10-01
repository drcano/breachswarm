"""Live self-check for the symbolic_solve primitive (angr). Real integration test: compiles a
crackme INSIDE the agent sandbox (ctf-agent image, where angr lives) and asserts symbolic
execution recovers the password from a stdout success string. Needs Docker + ctf-agent:latest.
Run: CTF_SANDBOX=docker ./.venv/bin/python verify_symbolic_solve.py
"""
import base64
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "primitives"))
import symbolic_solve
from sandbox import make_sandbox

CRACKME = r'''#include <stdio.h>
#include <string.h>
int main(void){
    char b[64];
    if(!fgets(b, sizeof(b), stdin)) return 1;
    b[strcspn(b, "\n")] = 0;
    if(strcmp(b, "h4ckm3") == 0) puts("Correct! flag{symb0lic_s0lv3}");
    else puts("Nope");
    return 0;
}'''

if __name__ == "__main__":
    wd = tempfile.mkdtemp()
    with make_sandbox(wd, network=False) as sb:
        b64 = base64.b64encode(CRACKME.encode()).decode()
        built = sb.bash(f"echo {b64} | base64 -d > /work/c.c && "
                        f"gcc -O0 -no-pie -o /work/crackme /work/c.c && echo BUILT")
        assert "BUILT" in built, f"crackme compile failed:\n{built}"
        out = symbolic_solve.run(sb, {"binary": "/work/crackme", "find": "Correct",
                                      "stdin_len": 16})
        print(out.strip())
        assert "SYMBOLIC_SOLVE_OK" in out, "angr did not reach the win state"
        assert "h4ckm3" in out, f"wrong input recovered:\n{out}"
        # a wrong win-string must NOT falsely 'solve'
        neg = symbolic_solve.run(sb, {"binary": "/work/crackme", "find": "this_never_prints",
                                      "stdin_len": 8})
        assert "SYMBOLIC_SOLVE_FAIL" in neg, "should not find an unreachable target"
    print("  ok  symbolic_solve recovered the crackme password (h4ckm3) via angr")
    print("  ok  reports failure on an unreachable win condition")
    print("\nsymbolic_solve verified: angr solves a crackme from a stdout success string, one call")
