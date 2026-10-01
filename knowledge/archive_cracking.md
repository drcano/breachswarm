## Password Cracking: Archives, Docs & Hashes
General flow: extract a crackable hash -> run `john`/`hashcat` against `rockyou.txt` (+ rules `-r best64.rule`), or a targeted mask if the format is known (`?d?d?d?d`).
Archives:
- ZIP: `zip2john file.zip > h; john h --wordlist=rockyou.txt`. ZipCrypto known-plaintext -> `bkcrack` (need ~12 known plaintext bytes of a contained file — often a known header). AES-zip -> hashcat `-m 13600`.
- RAR: `rar2john`; 7z: `7z2john` (`-m 11600`); PDF: `pdf2john` (`-m 10500` etc.); Office: `office2john` (`-m 9400/9500/9600`); KeePass: `keepass2john`; bitlocker/luks: `bitlocker2john`/`hashcat -m 22100`.
- SSH key: `ssh2john id_rsa`; GPG: `gpg2john`.
Steghide-protected (image/audio): `stegseek file rockyou.txt` (very fast), or `steghide extract -sf f -p <pw>`.
Hashes: identify (`hashid`), pick hashcat mode (`-m 0` MD5, `100` SHA1, `1400` SHA256, `1800` sha512crypt, `3200` bcrypt, `1000` NTLM, `22000` WPA/PMKID, `16800` PMKID). `--show` to display cracked. Google the hash first — many CTF hashes are known.
JWT/HMAC secrets: `hashcat -m 16500 jwt rockyou.txt`.
Tips: try empty password and obvious ones first; check the challenge text for a hint at the charset/length to build a mask instead of a full wordlist run.
