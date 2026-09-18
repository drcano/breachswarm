## Prototype Pollution (JS/Node)
Where: Node apps merging user JSON into objects (`Object.assign`, lodash `merge`/`set`, `deepmerge`, query parsers), config loaders, `req.query`/`req.body` spread into options.
Inject: send keys `__proto__`, `constructor.prototype` -> `{"__proto__":{"polluted":"x"}}` or query `?__proto__[polluted]=x` / `?constructor[prototype][polluted]=x`. Then `({}).polluted === "x"` app-wide.
Client-side (DOM PP): sink gadgets in the page merge `location`/`postMessage` data -> pollute `__proto__` to inject `srcdoc`/`src`/`innerHTML` gadget -> XSS.
Server-side escalation (pick the gadget the framework uses):
- RCE: pollute `NODE_OPTIONS`/`--require`, `shell`/`env` used by `child_process.spawn`, EJS/Pug/Handlebars template options (`outputFunctionName`, `escapeFunction`) -> code exec.
- AuthZ bypass: pollute `isAdmin`/`role`/`user` defaults read later.
- SSRF/redirect: pollute default URL/host options.
Detect: after sending payload, request an endpoint that reflects object state or errors differently; `{"__proto__":{"toString":0}}` often throws.
Escalate: SSRF/RCE via gadget, auth bypass, DoS. Tools: `ppmap`, manual gadget hunt in source.
