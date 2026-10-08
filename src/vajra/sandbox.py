"""Tool admission sandbox.

Every tool an MCP server offers is held in the sandbox before the planner may
see it. Deterministic, structural checks run on its definition; a tool that
fails any check is *burned* (never exposed). Only admitted tools reach the
planner. No model is asked: the checks look at structure, not meaning.

Server processes are also started sandboxed: an isolated temporary working
directory and only the environment variables the operator configured (plus the
SDK's minimal defaults). This is process-level isolation, not a container.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass

import mcp_types as types

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_DESCRIPTION = 1024
RESERVED_NAMES = frozenset({"quarantine"})


@dataclass(frozen=True)
class Admission:
    server: str
    tool: str
    admitted: bool
    reason: str | None
    fingerprint: str


def hidden_characters(text: str) -> list[str]:
    """Invisible format/control characters (zero-width, bidi overrides, …), rendered as U+XXXX."""
    return sorted(
        {f"U+{ord(c):04X}" for c in text if unicodedata.category(c) == "Cf" or (unicodedata.category(c) == "Cc" and c not in "\n\t\r")}
    )


def inspect_tool(tool: types.Tool, *, fingerprint: str, pin: str | None, taken: set[str]) -> str | None:
    """Return why the tool must be burned, or None if it is admitted."""
    if pin is not None and pin != fingerprint:
        return "definition changed since it was reviewed (pin mismatch)"
    if not NAME_RE.match(tool.name):
        return "invalid tool name"
    if tool.name in RESERVED_NAMES or tool.name in taken:
        return "same name as a tool from another server (shadowing)"
    definition = "\n".join([tool.name, tool.description or "", json.dumps(tool.input_schema, ensure_ascii=False)])
    hidden = hidden_characters(definition)
    if hidden:
        return f"hidden characters in its definition ({', '.join(hidden)})"
    if len(tool.description or "") > MAX_DESCRIPTION:
        return f"description longer than {MAX_DESCRIPTION} characters"
    if tool.input_schema.get("type") != "object":
        return "input schema is not an object"
    return None
