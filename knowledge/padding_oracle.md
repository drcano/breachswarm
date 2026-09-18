## Padding Oracle & AES Mode Attacks
Padding oracle (CBC): the app decrypts attacker ciphertext and REVEALS (via error/status/timing) whether PKCS#7 padding is valid.
- Exploit: byte-by-byte, manipulate the previous block to force valid padding -> recover intermediate state -> plaintext, with NO key. Also forge arbitrary ciphertext (encrypt) the same way.
- Tool: `padbuster URL ENCRYPTED_SAMPLE BLOCKSIZE -cookies ...`, or scriptable oracle loop. Signals: distinct 500 vs 200, "invalid padding" vs "invalid mac", timing delta.
CBC bit-flipping (no padding oracle needed): flipping a byte in ciphertext block C[i] flips the same byte in plaintext P[i+1] (garbling C[i]). Use to tamper structured plaintext — e.g. flip `role=user` -> `role=admin`, or `;admin=true`. Needs known/guessed plaintext at that offset.
ECB: identical plaintext blocks -> identical ciphertext blocks (detect by repeated 16-byte blocks). ECB cut-and-paste: rearrange blocks to forge tokens (`admin` block relocation). Byte-at-a-time ECB decryption when you control a prefix appended before a secret (`AES-ECB(prefix||secret)`): align secret one byte into a block boundary and brute each byte.
CTR/GCM nonce reuse: same nonce+key twice -> XOR of plaintexts leaks (keystream reuse); GCM nonce reuse -> forge auth tag (recover H). 
Escalate: decrypt/forge session tokens -> auth bypass / privilege escalation.
