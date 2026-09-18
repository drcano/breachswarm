## RSA Attacks (CTF crypto)
Recon: factor N via factordb (`http://factordb.com`), then `d = inverse(e, (p-1)*(q-1))`. Auto-tool: `RsaCtfTool.py --publickey k.pub --uncipher ct` (tries all of the below).
Attack decision tree:
- Small e (e=3) + small message: plaintext^e < N -> `m = iroot(c, 3)` (integer cube root, no modulus involved).
- Small e + same message to many recipients: Hastad broadcast (CRT then eth root).
- N factorable: small N, or via factordb; close primes p≈q -> Fermat factorization (`abs(p-q)` small).
- Shared prime between two moduli: `gcd(N1, N2)` = p -> both broken.
- Small d (d < N^0.292): Wiener's attack (continued fractions) / Boneh-Durfee.
- Partial key exposure / known high bits: Coppersmith (use SageMath `small_roots`).
- Common modulus, two e with gcd(e1,e2)=1: extended Euclid -> recover m without d.
- Unpadded / textbook RSA malleability: `c' = c * (s^e)` blinding.
- LSB / parity oracle: binary-search m via repeated oracle queries.
Glue: pycryptodome `long_to_bytes`, `inverse`, `GCD`; sympy for `iroot`/factoring; SageMath for lattice/Coppersmith. Always print decoded plaintext bytes.
