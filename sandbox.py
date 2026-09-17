"""Per-challenge Docker sandbox. One container per challenge = clean state,
no way for the agent's shell to touch the host.

Uses the image built from Dockerfile.agent. The agent runs bash *inside* here,
never on the host.
"""
import subprocess
import time
import uuid
from pathlib import Path

IMAGE = "ctf-agent:latest"  # docker build -t ctf-agent:latest -f Dockerfile.agent .


class Sandbox:
    def __init__(self, workdir: Path, image: str = IMAGE, timeout: int = 60):
        self.workdir = Path(workdir)
        self.image = image
        self.timeout = timeout
        self.name = f"ctf-{uuid.uuid4().hex[:8]}"
        self.actions: list[dict] = []   # audit log: every command + output

    def __enter__(self) -> "Sandbox":
        # Mount the challenge workspace at /work; keep the container idle so we
        # can exec many commands against one persistent filesystem.
        # ponytail: no --network by default (crypto/rev/forensics need none).
        # Web/pwn challenges: add the target with --add-host or a shared network.
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", self.name,
             "-v", f"{self.workdir}:/work", "-w", "/work",
             self.image, "sleep", "infinity"],
            check=True, capture_output=True,
        )
        return self

    def bash(self, command: str) -> str:
        """Run one command in the container; return combined stdout+stderr."""
        try:
            p = subprocess.run(
                ["docker", "exec", self.name, "bash", "-lc", command],
                capture_output=True, text=True, timeout=self.timeout,
            )
            out = (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            out = f"[timeout after {self.timeout}s]"
        out = out[:20000]  # ponytail: hard cap so one noisy command can't blow the context
        self.actions.append({"t": time.time(), "kind": "cmd",
                             "command": command, "output": out})
        return out

    def __exit__(self, *exc) -> None:
        subprocess.run(["docker", "kill", self.name], capture_output=True)
