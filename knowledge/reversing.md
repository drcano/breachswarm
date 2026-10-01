## Reverse Engineering
Triage: `file`, `strings -a` (+ `-e l`/`-e b` for UTF-16), `checksec`, run it and observe. The flag or a decisive constant is often already in `strings`.
Packed? (`upx -d`, high entropy, tiny import table) unpack first.
Scripts/bytecode: Python `.pyc` -> `decompyle3`/`uncompyle6` or `pycdc`; PyInstaller EXE -> `pyinstxtractor` then decompile; `.jar`/`.class` -> `jd-gui`/`procyon`/`cfr`; .NET -> `ilspycmd`/dnSpy; Go/Rust -> big static bins, use symbols + strings; WASM -> `wasm2wat`; Android `.apk` -> `jadx`.
Native: decompile (Ghidra/r2ghidra `pdg`, IDA, Binary Ninja). READ the pseudo-C for the check: comparison against a constant, XOR/add loop over input, a byte table, a checksum.
Solve the check:
- Simple transform (xor/add/sub with a key, per-char): invert it in Python.
- `input == secret` after transformation: reverse the transform on the stored constant.
- Complex/branchy license or keygen: `angr` — set `find=<success addr>`, `avoid=<fail addr>`, `simgr.explore()`, read the stdin (`state.posix.dumps(0)`). Time-box ~120s; constrain input length/charset to tame path explosion.
- Anti-debug/ptrace/timing checks: patch the jump (`radare2 wa`), or NOP the check, or set the env/register in a debugger.
- VM-based / custom bytecode: recover the opcode handler table, write a disassembler.
Dynamic: `ltrace`/`strace` for `strcmp`/`memcmp` of your input vs the secret (instant win on naive checks); `gdb` breakpoint on the compare.
