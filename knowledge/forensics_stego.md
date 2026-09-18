## Forensics: Files, Images & Stego
Triage EVERY file: `file`, `strings -a` (+ `-e l`/`-e b`), `xxd | head`, `exiftool -a -u -G1` (flags hide in metadata/comments), `binwalk -Me` (extract embedded/appended files — a huge fraction of forensics is "a file inside a file"), check for appended data after the real EOF marker.
Magic-byte fixes: wrong/broken header (PNG `89 50 4E 47`, JPG `FF D8 FF`, ZIP `50 4B 03 04`, PDF `25 50 44 46`) -> fix the header to open it; wrong extension -> re-detect with `file`.
Images:
- PNG/BMP: `zsteg -a` (LSB, channels), check bit-planes (`stegsolve`), IDAT/chunk anomalies (`pngcheck -v`), dimensions crop hiding data.
- JPEG: `steghide extract -sf f.jpg -p ''` (try empty + rockyou), `stegseek f.jpg rockyou.txt` (fast steghide brute), `exiftool`, `outguess`.
- Any: `strings`, `binwalk`, `foremost`, `zsteg`; QR/barcode -> `zbarimg`; look for `flag{` in raw bytes.
Audio: `sonic-visualiser`/`audacity` spectrogram (text drawn in frequencies), LSB (`WavSteg`), DTMF/morse tones, slowed/reversed.
Misc: `pdf-parser`/`peepdf` for PDFs (objects, JS), `oletools`/`olevba` for Office macros, disk images (`mmls`,`fls`,`icat` via Sleuth Kit), filesystem carving.
Recover deleted/hidden: `photorec`, slack space, alternate data streams (Windows).
