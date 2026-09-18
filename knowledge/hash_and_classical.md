## Hash Attacks & Classical Crypto
Hash length extension: MAC = `H(secret || message)` with H in (MD5/SHA1/SHA256) and known message + known secret LENGTH -> append data and forge a valid MAC WITHOUT the secret. Tool: `hashpump`/`hash_extender -d msg -s sig -a append -k <keylen>`. Signal: a `sig=` over `user=...&role=user` that you want to extend to `&role=admin`.
Hash cracking: identify (`hashid`/`hash-identifier`), crack with `john`/`hashcat -m <mode> hash rockyou.txt` (`-m 0` MD5, `1000` NTLM, `1800` sha512crypt, `3200` bcrypt, `22000` WPA). Rules `-r best64.rule`. Google the hash first for known values.
Weak/predictable secrets: JWT/session HMAC keys -> crack with rockyou; default keys.

## Classical / Encoding Ciphers
Identify first: `ciphey -t "<blob>"` or reason by charset. Base64 (`=`), base32 (A-Z2-7), hex, binary, decimal, ascii85, uuencode — many flags are NESTED encodings; peel until printable.
Substitution family: Caesar/ROT-N (try all 25 + ROT47 programmatically), Atbash, Vigenere (crack with `vigenere-solver`/known key or Kasiski), affine, substitution (`quipqiup`/frequency analysis).
Transposition: rail-fence, columnar, scytale — try common rails/keys.
Others: Morse (`.-`), Bacon, XOR (single-byte: brute 0-255 scoring printable; multi-byte: `xortool` for key length then frequency), one-time-pad reuse (crib-drag), Playfair, Hill, book cipher, brainfuck/esolang, tap code.
Always print the DECODED plaintext, never the ciphertext. If output looks like another cipher, decode again.
