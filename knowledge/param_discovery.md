## Hidden Parameter Discovery — unlock invisible attack surface
Endpoints frequently honor params that appear nowhere in the HTML/JS. A hidden param is a fresh sink:
`debug=`/`admin=`/`test=` flip privilege; `url=`/`redirect=`/`dest=`/`callback=` reach SSRF/open-redirect;
`file=`/`path=`/`template=` reach LFI/SSTI; `id=`/`user=`/`account=` reach IDOR. Finding the param is
usually the whole bug.

How discovery works: send the endpoint a large wordlist of candidate names and diff the response
(status, length, reflected value, new field, error change) against a baseline of a junk param. A param
that changes the response is "wired in". Test in every location — the app may read only one:
GET query, POST form (`application/x-www-form-urlencoded`), and JSON body (`{"name":val}`). Also try
header params (`X-*`) and array/object forms `name[]=`, `filter[key]=`.

Tools:
- `arjun -u https://t/api/x -m GET,POST,JSON -t 10 -oJ out.json` (s0md3v; built-in ~26k wordlist,
  auto handles GET/POST/JSON, rate-limit aware). `arjun -i urls.txt` for a list.
- `x8 -u https://t/api/x -w wordlists/params.txt` (Rust, fast, response-diff; good when arjun is slow).
- Burp **Param Miner** ("Guess GET/POST params", "Guess headers") — also finds unkeyed cache headers.

Mine names before brute-forcing (higher hit rate, quieter): pull param names from the app's own JS
bundles and source maps (`grep -oE '[?&][a-zA-Z_]+='`, `searchParams.get('...')`, `req.query.X`),
from Swagger/OpenAPI, from `__NEXT_DATA__`/inline config, and from other endpoints' requests.

High-value hidden names to always try: `debug`, `test`, `admin`, `is_admin`, `role`, `access`,
`internal`, `preview`, `draft`, `id`, `user_id`, `account`, `email`, `url`, `uri`, `redirect`,
`next`, `return`, `callback`, `dest`, `path`, `file`, `page`, `template`, `include`, `format`,
`callback`, `jsonp`, `xml`, `key`, `token`, `api_key`, `fields`, `expand`, `include`, `filter`.

After a hit: classify the sink and pivot — reflected/echoed → XSS; fetches a URL → [[ssrf]]/[[open_redirect]];
reads a file → [[lfi_path_traversal]]; controls object id → [[idor_bola]]; toggles state/role →
[[business_logic]]/[[mass_assignment]]. Then feed the artifact into [[chains]].
