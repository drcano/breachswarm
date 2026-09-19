"""symbolic_solve — an executable exploit PRIMITIVE for reverse engineering (angr).

The hard non-web ceiling: crackme-style binaries that check an input and print success.
A human reverses the check; symbolic execution just SOLVES for the input. angr is already in
the agent image, but the agent rarely reaches for it — this makes it one call: give a binary
and a win condition (a success STRING printed on stdout, or a target ADDRESS), and it returns
the concrete stdin/argv that reaches it. Collapses "reverse the algorithm by hand" into a solve.

Ceiling (honest): symbolic execution state-explodes on heavy loops/crypto and is bounded by the
sandbox's per-command timeout — veritesting is on to help, but this is for constraint-style
crackmes, not KDF/AES checks. For PIE binaries a raw file address may not match angr's load base,
so prefer a stdout success STRING (the default mode) over an address when possible.
"""
import base64
import json


def _script(params: dict) -> str:
    return "import json,sys\n" + \
           f"P=json.loads(r'''{json.dumps(params)}''')\n" + r'''
import logging
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
try:
    import angr
    try:
        import claripy                       # older angr: separate package
    except Exception:
        claripy = angr.claripy               # angr 10.x bundles it (angr.rustylib.claripy)
except Exception as e:
    print("SYMBOLIC_SOLVE_FAIL: angr not available: %s"%e); sys.exit(0)

BIN=P["binary"]; FIND=P["find"].strip(); AVOID=(P.get("avoid") or "").strip()
N=int(P.get("stdin_len",32)); USE_ARGV=bool(P.get("argv",False))

try:
    proj=angr.Project(BIN, auto_load_libs=False)
except Exception as e:
    print("SYMBOLIC_SOLVE_FAIL: could not load %r: %s"%(BIN,e)); sys.exit(0)

sym=claripy.BVS("in", N*8)
if USE_ARGV:
    state=proj.factory.entry_state(args=[BIN, sym])
else:
    state=proj.factory.entry_state(stdin=sym)      # symbolic stdin of N bytes

def _target(spec):                                  # 0x.. -> address, else stdout substring
    if spec.startswith("0x"):
        try: return int(spec,16)
        except ValueError: return spec.encode()
    return spec.encode()

find=_target(FIND); avoid=_target(AVOID) if AVOID else None
simgr=proj.factory.simulation_manager(state, veritesting=True)
def _f(s):
    return (s.addr==find) if isinstance(find,int) else (find in s.posix.dumps(1))
def _a(s):
    if avoid is None: return False
    return (s.addr==avoid) if isinstance(avoid,int) else (avoid in s.posix.dumps(1))
try:
    simgr.explore(find=_f, avoid=_a)
except Exception as e:
    print("SYMBOLIC_SOLVE_FAIL: exploration error (state explosion/timeout?): %s"%e); sys.exit(0)

if simgr.found:
    s=simgr.found[0]
    if USE_ARGV:
        raw=s.solver.eval(sym, cast_to=bytes)
    else:
        raw=s.posix.dumps(0)
    printable=raw.split(b"\x00")[0]
    out=s.posix.dumps(1)[:300]
    print("SYMBOLIC_SOLVE_OK")
    print("INPUT_BYTES:", raw)
    print("INPUT:", printable.decode("latin-1"))
    print("STDOUT:", out.decode("latin-1"))
else:
    print("SYMBOLIC_SOLVE_FAIL: no state reached the target — check find/avoid (try a stdout "
          "success string), raise stdin_len, or the binary may need argv (set argv=true).")
'''


def run(sb, args: dict) -> str:
    binary = (args.get("binary") or "").strip()
    if not binary:
        return ("symbolic_solve error: 'binary' is required — the path to the target binary in "
                "the sandbox (e.g. /work/crackme).")
    if not (args.get("find") or "").strip():
        return ("symbolic_solve error: 'find' is required — the win condition: a success STRING "
                "printed on stdout (e.g. 'Correct') or a target address (e.g. '0x401234').")
    params = {"binary": binary, "find": args["find"], "avoid": args.get("avoid") or "",
              "stdin_len": int(args.get("stdin_len") or 32), "argv": bool(args.get("argv"))}
    b64 = base64.b64encode(_script(params).encode()).decode()
    return sb.bash(f"echo {b64} | base64 -d | python3 -")
