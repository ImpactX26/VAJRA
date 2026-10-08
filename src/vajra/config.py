"""Proxy configuration (TOML).

Everything security-relevant is declared here by the operator and evaluated
by deterministic code. Defaults fail closed: upstream output is untrusted and
no tool argument may receive untrusted data unless explicitly allowed.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .taint.labels import Integrity

_UPSTREAM_NAME = re.compile(r"^[A-Za-z0-9-]+$")
NAMESPACE_SEP = "__"


class Delivery(StrEnum):
    OPAQUE = "opaque"
    """Untrusted output is replaced by a handle; the planner never sees it."""
    INLINE = "inline"
    """Untrusted output reaches the planner, which taints the whole session context."""


@dataclass(frozen=True)
class ToolConfig:
    output: Integrity | None = None
    """Integrity of this tool's output. ``None`` inherits the upstream default."""
    untrusted_args: frozenset[str] = frozenset()
    """Arguments permitted to carry untrusted data (e.g. an email *body*, never its recipient)."""
    allow_tainted_invocation: bool = False
    """Whether the tool may be invoked at all once the planner context is tainted."""
    description: str | None = None
    """Operator-written description replacing the upstream's (which is itself untrusted text)."""
    hidden: bool = False


@dataclass(frozen=True)
class UpstreamConfig:
    name: str
    command: str
    args: tuple[str, ...] = ()
    env: dict[str, str] | None = None
    cwd: str | None = None
    output: Integrity = Integrity.UNTRUSTED
    tools: dict[str, ToolConfig] = field(default_factory=dict)

    def tool(self, name: str) -> ToolConfig:
        return self.tools.get(name, ToolConfig())

    def tool_output(self, name: str) -> Integrity:
        override = self.tool(name).output
        return self.output if override is None else override


@dataclass(frozen=True)
class VajraConfig:
    name: str = "vajra"
    delivery: Delivery = Delivery.OPAQUE
    upstreams: dict[str, UpstreamConfig] = field(default_factory=dict)


def load_config(path: str | Path) -> VajraConfig:
    with open(path, "rb") as f:
        return parse_config(tomllib.load(f))


def parse_config(raw: dict[str, Any]) -> VajraConfig:
    proxy = raw.get("proxy", {})
    upstreams = {name: _parse_upstream(name, body) for name, body in raw.get("upstreams", {}).items()}
    return VajraConfig(
        name=proxy.get("name", "vajra"),
        delivery=Delivery(proxy.get("delivery", Delivery.OPAQUE)),
        upstreams=upstreams,
    )


def _parse_upstream(name: str, body: dict[str, Any]) -> UpstreamConfig:
    if not _UPSTREAM_NAME.match(name) or NAMESPACE_SEP in name:
        raise ValueError(f"upstream name {name!r} must match [A-Za-z0-9-]+")
    tools = {tool: _parse_tool(tool_body) for tool, tool_body in body.get("tools", {}).items()}
    return UpstreamConfig(
        name=name,
        command=body["command"],
        args=tuple(body.get("args", ())),
        env=body.get("env"),
        cwd=body.get("cwd"),
        output=Integrity.parse(body.get("output", "untrusted")),
        tools=tools,
    )


def _parse_tool(body: dict[str, Any]) -> ToolConfig:
    output = body.get("output")
    return ToolConfig(
        output=Integrity.parse(output) if output is not None else None,
        untrusted_args=frozenset(body.get("untrusted_args", ())),
        allow_tainted_invocation=bool(body.get("allow_tainted_invocation", False)),
        description=body.get("description"),
        hidden=bool(body.get("hidden", False)),
    )
