## Pwn: Stack Overflow & ROP
Triage: `checksec` -> NX/PIE/RELRO/Canary decide strategy. `file`, run it, find input that crashes.
Find offset: `cyclic 200` as input, read crashing `$rip`/`$pc`, `cyclic_find <val>` -> exact offset to return address. pwntools: `p=process('./x'); p.sendline(cyclic(200))`.
No canary + NX off (rare): shellcode on stack, jump to it (`jmp rsp` gadget or leaked stack addr).
No canary + NX on -> ROP:
- ret2win: overflow -> address of a win()/flag function.
- ret2libc: leak a libc addr (call `puts@plt` with `puts@got`), compute libc base, then 2nd payload -> `system("/bin/sh")`. Find offsets via `libc-database`/known libc; `one_gadget ./libc.so.6` for a single RCE gadget.
- Build chains: `ROP(elf)`, `ROPgadget --binary ./x` / `ropper`; `rop.raw(...)`, `rop.call('system',[binsh])`; need `pop rdi; ret` (arg1), `pop rsi; ret`, `ret` for stack alignment (movaps).
Canary present: leak it first (format string / partial overwrite / off-by-one) then include it in the payload. PIE: leak a code/stack addr to defeat ASLR before jumping.
GOT overwrite (Partial/No RELRO): overwrite a GOT entry with `system`/one_gadget.
Remote: solve local with `process`, then `remote(host,port)`; match the remote libc.
Template: pwntools `context.binary`, `p.recvuntil`, `p.sendlineafter`, `p.interactive()`; then `cat flag`.
