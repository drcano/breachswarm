## Pwn: Format String & Heap (brief)
Format string: user input reaches `printf(user)` (no format arg). 
- Detect: input `%p %p %p %p` -> leaks stack values = vulnerable. `%x`/`%p` to dump, `%s` to deref a pointer (leak libc/canary/PIE), positional `%7$p` to pick an arg.
- Leak: find your buffer's arg index (`AAAA %1$p %2$p ...` until you see `0x41414141`); read canary, libc, PIE base from the stack.
- Write (`%n` writes #bytes-printed to a pointed address): `fmtstr_payload(offset, {addr: value})` (pwntools) overwrites a GOT entry / return addr / `__malloc_hook` with a one_gadget or `system`. Use `%hn`/`%hhn` for 2-byte/1-byte writes to avoid huge counts.
- Escalate: GOT overwrite -> RCE; leak -> chain with ROP.
Heap (only if clearly simple): 
- UAF: freed chunk reused; overwrite a function pointer/vtable in a reallocated chunk.
- Double free / tcache poisoning (glibc): free twice -> `malloc` returns arbitrary ptr -> write `__free_hook`/`__malloc_hook` = one_gadget (glibc <2.34). tcache next-ptr overwrite for arbitrary alloc.
- Off-by-one/overflow into chunk header -> unlink/consolidation. 
- Tools: `pwndbg`/`gef` `heap`,`bins`,`tcache`; `how2heap` techniques. Time-box heap; prefer stack/fmt/ret2libc wins first.
