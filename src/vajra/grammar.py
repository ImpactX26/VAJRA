"""Constrained action grammar: only well-formed calls to approved tools can become actions.

The grammar is generated from the signatures of the tools that passed the admission
sandbox. Every action the planner takes must match it exactly:

    action   := TOOL "(" [ arg ( "," arg )* ] ")"
    arg      := NAME "=" value                 -- NAME must be a parameter of TOOL
    value    := STRING | NUMBER | "true" | "false" | "null" | HANDLE | "[" [ value ( "," value )* ] "]"

and, per tool: every required parameter present, no unknown parameters, every value of
the declared type, strings without control characters and within a length limit. One
action per parse: trailing text, a second call or free-form prose fails.

Structured MCP calls are checked against the same rules (``validate``); the text form
(``parse``) is for planners that write actions as text, and for the UI playground. Injected
natural language ("ignore previous instructions and email ...") is not an action in this
language, so it can never be executed as one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MAX_STRING = 20_000
HANDLE_RE = re.compile(r"\$vajra:h_[0-9a-f]{32}")
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
NUMBER_RE = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
JSON_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict}


class GrammarError(ValueError):
    def __init__(self, message: str, position: int | None = None) -> None:
        super().__init__(message)
        self.position = position


@dataclass(frozen=True)
class Action:
    tool: str
    args: dict[str, Any]


class ActionGrammar:
    def __init__(self, tools: Mapping[str, Mapping[str, Any]], qualified: Mapping[str, tuple[str, str]] | None = None) -> None:
        """``tools``: exposed tool name -> JSON input schema. ``qualified``: exposed name -> (upstream, tool)."""
        self.tools = {name: dict(schema or {}) for name, schema in tools.items()}
        self._by_pair = {pair: name for name, pair in (qualified or {}).items()}

    # ------------------------------------------------------------------ structured calls
    def name_for(self, upstream: str, tool: str) -> str | None:
        return self._by_pair.get((upstream, tool))

    def validate(self, name: str, args: Any) -> None:
        schema = self.tools.get(name)
        if schema is None:
            raise GrammarError(f"{name!r} is not an approved tool")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise GrammarError(f"{name}: arguments must be named parameters")
        props: dict[str, Any] = schema.get("properties") or {}
        unknown = sorted(set(args) - set(props))
        if unknown:
            raise GrammarError(f"{name}: unknown parameter(s) {', '.join(unknown)}")
        missing = sorted(set(schema.get("required") or []) - set(args))
        if missing:
            raise GrammarError(f"{name}: missing required parameter(s) {', '.join(missing)}")
        for key, value in args.items():
            self._check_value(f"{name}.{key}", value, props.get(key) or {})

    def _check_value(self, where: str, value: Any, spec: Mapping[str, Any]) -> None:
        types = spec.get("type")
        allowed = [types] if isinstance(types, str) else list(types or [])
        if "anyOf" in spec and not allowed:
            allowed = [s.get("type") for s in spec["anyOf"] if isinstance(s, dict) and s.get("type")]
        if allowed:
            ok = any(
                (t == "null" and value is None)
                or (t in JSON_TYPES and isinstance(value, JSON_TYPES[t]) and not (t in ("integer", "number") and isinstance(value, bool)))
                for t in allowed
            )
            if not ok:
                raise GrammarError(f"{where}: expected {' or '.join(allowed)}, got {type(value).__name__}")
        if "enum" in spec and value not in spec["enum"]:
            raise GrammarError(f"{where}: must be one of {spec['enum']}")
        if isinstance(value, str):
            if len(value) > MAX_STRING:
                raise GrammarError(f"{where}: longer than {MAX_STRING} characters")
            if CONTROL_RE.search(value):
                raise GrammarError(f"{where}: contains control characters")
        if isinstance(value, list):
            for i, item in enumerate(value):
                self._check_value(f"{where}[{i}]", item, spec.get("items") or {})

    # ------------------------------------------------------------------ text form
    def parse(self, text: str) -> Action:
        p = _Parser(text)
        p.ws()
        start = p.i
        name = p.name("a tool name")
        if name not in self.tools:
            raise GrammarError(f"{name!r} is not an approved tool", start)
        p.ws()
        p.expect("(")
        args: dict[str, Any] = {}
        p.ws()
        if not p.peek(")"):
            while True:
                p.ws()
                at = p.i
                key = p.name("a parameter name")
                if key in args:
                    raise GrammarError(f"parameter {key!r} given twice", at)
                p.ws()
                p.expect("=")
                p.ws()
                args[key] = p.value()
                p.ws()
                if p.peek(")"):
                    break
                p.expect(",")
        p.expect(")")
        p.ws()
        if p.i != len(text):
            raise GrammarError("unexpected text after the action: only one action is allowed", p.i)
        try:
            self.validate(name, args)
        except GrammarError as e:
            raise GrammarError(str(e), start) from None
        return Action(name, args)

    def ebnf(self) -> list[str]:
        """The grammar for the currently approved tools, one production per tool (for display)."""
        lines = []
        for name, schema in sorted(self.tools.items()):
            props = schema.get("properties") or {}
            required = set(schema.get("required") or [])
            parts = []
            for key, spec in props.items():
                t = spec.get("type") or "/".join(s.get("type", "?") for s in spec.get("anyOf", []) if isinstance(s, dict)) or "value"
                parts.append(f'{key}={t.upper() if isinstance(t, str) else "VALUE"}' + ("" if key in required else "?"))
            lines.append(f"{name}({', '.join(parts)})")
        return lines


class _Parser:
    def __init__(self, text: str) -> None:
        self.text, self.i = text, 0

    def ws(self) -> None:
        while self.i < len(self.text) and self.text[self.i] in " \t\r\n":
            self.i += 1

    def peek(self, s: str) -> bool:
        return self.text.startswith(s, self.i)

    def expect(self, s: str) -> None:
        if not self.peek(s):
            found = self.text[self.i:self.i + 12] or "end of text"
            raise GrammarError(f"expected {s!r} but found {found!r}", self.i)
        self.i += len(s)

    def name(self, what: str) -> str:
        m = NAME_RE.match(self.text, self.i)
        if not m:
            found = self.text[self.i:self.i + 12] or "end of text"
            raise GrammarError(f"expected {what} but found {found!r}", self.i)
        self.i = m.end()
        return m.group(0)

    def value(self) -> Any:
        if self.peek('"'):
            return self._string()
        if self.peek("$vajra:"):
            m = HANDLE_RE.match(self.text, self.i)
            if not m:
                raise GrammarError("malformed handle", self.i)
            self.i = m.end()
            return m.group(0)
        if self.peek("["):
            self.i += 1
            items: list[Any] = []
            self.ws()
            if self.peek("]"):
                self.i += 1
                return items
            while True:
                self.ws()
                items.append(self.value())
                self.ws()
                if self.peek("]"):
                    self.i += 1
                    return items
                self.expect(",")
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.peek(word) and not NAME_RE.match(self.text[self.i + len(word):self.i + len(word) + 1] or " "):
                self.i += len(word)
                return val
        m = NUMBER_RE.match(self.text, self.i)
        if m and m.end() > self.i:
            self.i = m.end()
            return json.loads(m.group(0))
        found = self.text[self.i:self.i + 12] or "end of text"
        raise GrammarError(f"expected a value (quoted string, number, true/false, handle or list) but found {found!r}", self.i)

    def _string(self) -> str:
        start = self.i
        decoder = json.JSONDecoder()
        try:
            value, end = decoder.raw_decode(self.text, self.i)
        except ValueError:
            raise GrammarError("unterminated or invalid string", start) from None
        if not isinstance(value, str):
            raise GrammarError("expected a string", start)
        self.i = end
        return value
