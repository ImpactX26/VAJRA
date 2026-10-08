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


# --------------------------------------------------------------------------- content sandbox
# Tool *output* that is HTML is cleaned before anything else sees it: everything a
# human reader would not see is burned. Like the admission checks, this is a fixed
# structural rule, not a judgement about meaning.

_DROP_TAGS = frozenset({"script", "style", "template", "noscript", "svg", "iframe", "object"})
_VOID_TAGS = frozenset({"br", "hr", "img", "input", "meta", "link", "area", "base", "col", "embed", "source", "track", "wbr"})
_BLOCK_TAGS = frozenset({"p", "div", "li", "ol", "ul", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "section", "article", "br", "pre", "table"})
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|font-size\s*:\s*[01](?:\.\d+)?(?:px|pt|em|rem)?\s*(?:;|$)",
    re.I,
)


@dataclass(frozen=True)
class Burned:
    kind: str
    """Why it was burned: hidden element, comment, script/style, invisible characters."""
    preview: str


def _is_hidden(tag: str, attrs: dict[str, str | None]) -> str | None:
    if tag in _DROP_TAGS:
        return f"<{tag}> block"
    if "hidden" in attrs:
        return "element with the hidden attribute"
    if (attrs.get("aria-hidden") or "").lower() == "true":
        return "element marked aria-hidden"
    if _HIDDEN_STYLE.search(attrs.get("style") or ""):
        return "element styled to be invisible"
    return None


def sanitize_html(html: str) -> tuple[str, list[Burned]]:
    """Return the text a person would see on the page, plus everything that was burned."""
    from html.parser import HTMLParser

    burned: list[Burned] = []

    class _Visible(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.out: list[str] = []
            self.hidden_depth = 0
            self.hidden_kind = ""
            self.hidden_text: list[str] = []
            self.stack: list[str] = []

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag in _VOID_TAGS:
                if tag == "br" and not self.hidden_depth:
                    self.out.append("\n")
                return
            self.stack.append(tag)
            if self.hidden_depth:
                self.hidden_depth += 1
                return
            kind = _is_hidden(tag, dict(attrs))
            if kind:
                self.hidden_depth, self.hidden_kind, self.hidden_text = 1, kind, []
            elif tag in _BLOCK_TAGS:
                self.out.append("\n")

        def handle_endtag(self, tag: str) -> None:
            if tag in _VOID_TAGS or tag not in self.stack:
                return
            while self.stack and self.stack.pop() != tag:
                pass
            if self.hidden_depth:
                self.hidden_depth -= 1
                if self.hidden_depth == 0:
                    text = " ".join("".join(self.hidden_text).split())
                    if text or self.hidden_kind.startswith("element"):
                        burned.append(Burned(self.hidden_kind, text[:300]))
            elif tag in _BLOCK_TAGS:
                self.out.append("\n")

        def handle_data(self, data: str) -> None:
            (self.hidden_text if self.hidden_depth else self.out).append(data)

        def handle_comment(self, data: str) -> None:
            text = " ".join(data.split())
            if text:
                burned.append(Burned("HTML comment", text[:300]))

    parser = _Visible()
    parser.feed(html)
    parser.close()
    text = "".join(parser.out)

    invisible = hidden_characters(text)
    if invisible:
        burned.append(Burned("invisible characters", ", ".join(invisible)))
        text = "".join(c for c in text if not (unicodedata.category(c) == "Cf" or (unicodedata.category(c) == "Cc" and c not in "\n\t\r")))

    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line), burned
