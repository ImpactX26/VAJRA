"""Operating-system isolation for upstream MCP servers.

Modes:
  * ``job``    : run the server under ``jail.py`` (Windows Job Object / POSIX rlimits).
                 Always available; enforces memory, CPU-time and process limits and kills
                 everything when VAJRA disconnects.
  * ``docker`` : run the server in a throw-away container (no network unless allowed,
                 read-only filesystem, memory/CPU/PID limits). Used when Docker is installed
                 and the server image exists.
  * ``none``   : no OS isolation (only for the unprotected comparison).

Content checks (burning unsafe data) happen in VAJRA itself, after the isolated server
returns: see ``vajra.sandbox``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

JAIL = str(Path(__file__).with_name("jail.py"))
DOCKER_IMAGE = "vajra-mcp-servers"


@dataclass(frozen=True)
class Limits:
    memory_mb: int = 256
    cpu_seconds: int = 60
    max_processes: int = 3
    """Jailer + the server's interpreter (+ a launcher on Windows venvs). The server cannot start anything else."""


@dataclass(frozen=True)
class ContainerSpec:
    """How to run one server in Docker. Paths in ``command``/``args`` are container paths."""

    command: str
    args: tuple[str, ...]
    mounts: tuple[tuple[str, str, bool], ...] = ()  # (host path, container path, read_only)
    network: bool = False
    env: dict[str, str] = field(default_factory=dict)


@lru_cache(maxsize=1)
def docker_ready(image: str = DOCKER_IMAGE) -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def jail_command(command: str, args: list[str], limits: Limits = Limits()) -> tuple[str, list[str]]:
    return sys.executable, [
        JAIL, "--memory-mb", str(limits.memory_mb), "--cpu-seconds", str(limits.cpu_seconds),
        "--max-processes", str(limits.max_processes), "--", command, *args,
    ]


def docker_command(spec: ContainerSpec, limits: Limits = Limits(), image: str = DOCKER_IMAGE) -> tuple[str, list[str]]:
    args = [
        "run", "--rm", "-i", "--read-only", "--tmpfs", "/tmp",
        f"--memory={limits.memory_mb}m", "--cpus=1", "--pids-limit=32",
        "--security-opt=no-new-privileges", "--cap-drop=ALL",
    ]
    if spec.network:
        args += ["--add-host=host.docker.internal:host-gateway"]
    else:
        args += ["--network=none"]
    for host, container, ro in spec.mounts:
        args += ["-v", f"{host}:{container}{':ro' if ro else ''}"]
    for k, v in spec.env.items():
        args += ["-e", f"{k}={v}"]
    return "docker", [*args, image, spec.command, *spec.args]


def describe(mode: str, limits: Limits = Limits(), network: bool = False) -> str:
    if mode == "docker":
        return f"Docker container ({'host-only network' if network else 'no network'}, read-only, {limits.memory_mb} MB)"
    if mode == "job":
        kind = "Windows Job Object" if sys.platform == "win32" else "OS resource limits"
        return f"{kind} ({limits.memory_mb} MB, {limits.cpu_seconds} s CPU, no extra processes)"
    return "no isolation"
