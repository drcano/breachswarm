"""Execution sandboxes for the solver. Two backends:

- DockerSandbox: one container per challenge (real isolation). Requires a docker
  runtime. Use for untrusted binaries (pwn/rev) and anything network-facing.
- LocalSandbox: runs commands on the host in the challenge dir. NO isolation.
  Dev/smoke-testing and trusted practice challenges (crypto/forensics/misc) only
  — never point it at an untrusted pwn/rev binary.

Both log every command+output to `.actions` (the audit trail) and share the
timeout + output cap.

Pick with make_sandbox(...) / the CTF_SANDBOX env var (local|docker).
"""
import os
import subprocess
import time
import uuid
from pathlib import Path

IMAGE = "ctf-agent:latest"  # docker build -t ctf-agent:latest -f Dockerfile.agent .
_OUT_CAP = 20000            # ponytail: cap so one noisy command can't blow the context


class _Base:
    def __init__(self, workdir, timeout: int = 60):
        self.workdir = Path(workdir)
        self.timeout = timeout
        self.actions: list[dict] = []

    def _log(self, command: str, out: str) -> str:
        out = (out or "")[:_OUT_CAP]
        self.actions.append({"t": time.time(), "kind": "cmd",
                             "command": command, "output": out})
        return out

    def bash(self, command: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class LocalSandbox(_Base):
    """Runs on the host. Unsafe for untrusted code — see module docstring."""

    def bash(self, command: str, timeout: int | None = None) -> str:
        t = timeout or self.timeout
        try:
            p = subprocess.run(["bash", "-lc", command], cwd=self.workdir,
                               capture_output=True, text=True, timeout=t)
            out = (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            out = f"[timeout after {t}s]"
        return self._log(command, out)


class DockerSandbox(_Base):
    """One container per challenge, workspace mounted at /work."""

    def __init__(self, workdir, image: str = IMAGE, timeout: int = 60,
                 network: bool = False, network_name: str | None = None,
                 proxy_url: str | None = None):
        super().__init__(workdir, timeout)
        self.image = image
        self.network = network
        self.network_name = network_name   # attach to a specific docker network
        self.proxy_url = proxy_url          # force all egress through this proxy
        self.name = f"ctf-{uuid.uuid4().hex[:8]}"

    def __enter__(self):
        # Security policy: no network by default, so an untrusted challenge binary
        # (pwn/rev/forensics) can't exfiltrate or call home. Web/osint pass
        # network=True to reach their (authorised) targets. For real-world work,
        # network_name pins an internal-only network whose sole egress is proxy_url
        # (see bounty.py --enforce) so scope is enforced at the wire, no bypass.
        if self.network_name:
            net = ["--network", self.network_name]
        elif self.network:
            net = []
        else:
            net = ["--network", "none"]
        env = []
        if self.proxy_url:
            for v in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                env += ["-e", f"{v}={self.proxy_url}"]
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", self.name, *net, *env,
             "-v", f"{self.workdir}:/work", "-w", "/work",
             self.image, "sleep", "infinity"],
            check=True, capture_output=True,
        )
        return self

    def bash(self, command: str, timeout: int | None = None) -> str:
        # Per-call override: normal agent commands stay at the snappy default (60s), but the
        # exploit primitives run PACED extractions (~100-250s for a long blind flag) that must
        # be allowed to finish — the 60s cap silently killed them and drove the agent to a
        # background-nohup-and-poll anti-pattern instead of just calling the primitive.
        t = timeout or self.timeout
        try:
            p = subprocess.run(
                ["docker", "exec", self.name, "bash", "-lc", command],
                capture_output=True, text=True, timeout=t,
            )
            out = (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            out = f"[timeout after {t}s]"
        return self._log(command, out)

    def __exit__(self, *exc):
        subprocess.run(["docker", "kill", self.name], capture_output=True)
        return False


def make_sandbox(workdir, backend: str | None = None, network: bool = False,
                 network_name: str | None = None, proxy_url: str | None = None,
                 **kw) -> _Base:
    backend = backend or os.environ.get("CTF_SANDBOX", "docker")
    if backend == "local":
        return LocalSandbox(workdir, **kw)          # local has host network anyway
    return DockerSandbox(workdir, network=network, network_name=network_name,
                         proxy_url=proxy_url, **kw)
