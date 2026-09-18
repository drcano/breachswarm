# MCP Integration in an Agentic System

How this project wires **Model Context Protocol (MCP)** servers into the agent
loop, and the two integration patterns an FDE meets in the field. MCP is how you
give an agent new capabilities — a customer's internal tools, a decompiler, a
database — without changing the model. Getting this wiring right *is* a lot of
forward-deployed work.

## The loop

Each specialist is a `query(prompt, options)` call. Capabilities are attached via
`ClaudeAgentOptions.mcp_servers` (a name→server map) and gated by `allowed_tools`
(`mcp__<server>__<tool>`). The model can only call tools you list.

```python
servers = {"ctf": _sandbox_server(sb)}          # shell in the sandbox
tools   = ["mcp__ctf__sandbox_bash"]
if spec in ("rev", "pwn"):                        # binary work also gets a decompiler
    servers["decomp"] = _decompiler_server(sb)
    tools.append("mcp__decomp__decompile")
options = ClaudeAgentOptions(system_prompt=SPECIALISTS[spec],
                             mcp_servers=servers, allowed_tools=tools, max_turns=n)
```

This is **multi-server wiring**: two independent MCP servers on one agent, each
exposing scoped tools, composed per specialist. `solver.py` is the reference.

## Pattern 1 — in-process SDK MCP server (what we use)

`create_sdk_mcp_server` + `@tool` runs the server *inside the Python process*. No
subprocess, no transport — best when the tool needs live objects from your app
(here, the per-challenge Docker sandbox handle `sb`).

```python
def _decompiler_server(sb):
    @tool("decompile", "Decompile a function to pseudo-C", {"binary": str, "function": str})
    async def decompile(args):
        out = sb.bash(f"r2 -q -A -c 's {args['function']}; pdg' '{args['binary']}'")
        return {"content": [{"type": "text", "text": out}]}
    return create_sdk_mcp_server(name="decomp", version="0.1", tools=[decompile])
```

The tool's *interface* (decompile a function → pseudo-C) is stable; the *backend*
is swappable — r2ghidra now, Ghidra `analyzeHeadless` or a cloud service later —
with zero change to the agent wiring.

## Pattern 2 — external MCP server (a customer's, or real GhidraMCP)

The same `mcp_servers` map also takes **external** servers the SDK launches as a
subprocess and speaks MCP to over stdio. This is the pattern for integrating a
tool you don't own — e.g. the community GhidraMCP:

```python
options = ClaudeAgentOptions(
    mcp_servers={
        "ghidra": {                       # external stdio server
            "type": "stdio",
            "command": "python",
            "args": ["-m", "ghidra_mcp"], # or the vendor's launch command
            "env": {"GHIDRA_INSTALL_DIR": "/opt/ghidra"},
        }
    },
    allowed_tools=["mcp__ghidra__decompile_function"],
)
```

Nothing else in the agent loop changes — you swap the server config, keep the
prompt and control flow. That decoupling is the point: **the agent doesn't care
whether a capability is 20 lines of in-process Python or a vendor's daemon.**

## Why we back the decompiler with r2ghidra, not full Ghidra

`decompile` is backed by **r2ghidra** (`pdg`) — Ghidra's decompiler engine as an
r2 plugin: Ghidra-quality pseudo-C, no JDK, no GUI, ~100–200MB vs Ghidra's ~2GB,
and no fragile GUI-plugin bridge. Same MCP interface as external GhidraMCP would
expose, so if a Ghidra-only feature is ever needed, Pattern 2 drops it in.
(Honest state: r2ghidra compiles from source via `r2pm` but currently **fails to
build in this image** — its configure can't find `r_core` via pkg-config with the
apt radare2. So today the tool returns annotated **disassembly** (r2's `pdc` pseudo-C
is empty/unreliable here); with r2ghidra it would return Ghidra-quality pseudo-C.
Either way the agent wiring is unchanged — that decoupling is the whole point.)

## FDE takeaways

- **Capabilities are data, not code changes.** Adding a tool = a server entry + an
  allowed-tools string. This is how you extend an agent for a customer fast.
- **Scope tools deliberately.** `allowed_tools` is the trust boundary; the
  decompiler is only exposed to rev/pwn, not every specialist.
- **Keep the interface, swap the backend.** In-process today, vendor daemon
  tomorrow — the agent loop is stable across both.
