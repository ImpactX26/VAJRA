"""Handle store for untrusted data.

Untrusted values are kept proxy-side and the planner only ever sees an opaque
handle token (``$vajra:h_<hex>``). The planner may place handle tokens in
tool-call arguments; the store substitutes the real value back in at call time
and reports the joined label of everything that was substituted.

Because the planner never observes untrusted bytes, injected instructions have
no path into the planner's context — this is the architectural core of the
defence, not a heuristic.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from .labels import TRUSTED, Label, join_all

HANDLE_PREFIX = "$vajra:"
HANDLE_RE = re.compile(r"\$vajra:(h_[0-9a-f]{32})")


class UnknownHandleError(LookupError):
    """A handle token did not resolve. Fails closed: the call is rejected."""


@dataclass(frozen=True, slots=True)
class TaintedValue:
    handle: str
    label: Label
    text: str
    """Text substituted wherever the handle token appears in an argument."""
    structured: Any = None
    """Upstream structured content, kept for schema-based extraction (not substituted)."""
    mime_type: str | None = None

    @property
    def token(self) -> str:
        return f"{HANDLE_PREFIX}{self.handle}"


@dataclass
class TaintStore:
    _values: dict[str, TaintedValue] = field(default_factory=dict)

    def put(self, label: Label, text: str, structured: Any = None, mime_type: str | None = None) -> TaintedValue:
        # 128 bits of randomness: handles are capabilities to *reference* data and
        # must not be guessable.
        handle = f"h_{secrets.token_hex(16)}"
        value = TaintedValue(handle, label, text, structured, mime_type)
        self._values[handle] = value
        return value

    def get(self, handle: str) -> TaintedValue:
        try:
            return self._values[handle]
        except KeyError:
            raise UnknownHandleError(f"unknown handle {handle!r}") from None

    def __len__(self) -> int:
        return len(self._values)

    def resolve(self, obj: Any) -> tuple[Any, Label]:
        """Substitute handle tokens anywhere in a JSON-like value.

        Returns the resolved value and the join of every substituted label.
        """
        if isinstance(obj, str):
            return self._resolve_str(obj)
        if isinstance(obj, list):
            items = [self.resolve(v) for v in obj]
            return [v for v, _ in items], join_all(l for _, l in items)
        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            label = TRUSTED
            for k, v in obj.items():
                rk, kl = self.resolve(k) if isinstance(k, str) else (k, TRUSTED)
                rv, vl = self.resolve(v)
                out[rk] = rv
                label = label | kl | vl
            return out, label
        return obj, TRUSTED

    def resolve_arguments(self, arguments: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Label]]:
        """Resolve top-level tool arguments, keeping a label per argument for policy checks."""
        resolved: dict[str, Any] = {}
        labels: dict[str, Label] = {}
        for name, value in (arguments or {}).items():
            resolved[name], labels[name] = self.resolve(value)
        return resolved, labels

    def _resolve_str(self, s: str) -> tuple[str, Label]:
        # Always the text form: without the target parameter's schema, substituting structured data
        # could silently change an argument's type.
        label = TRUSTED

        def sub(m: re.Match[str]) -> str:
            nonlocal label
            value = self.get(m.group(1))
            label = label | value.label
            return value.text

        return HANDLE_RE.sub(sub, s), label
