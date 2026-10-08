"""Taint-tracking middleware.

Sits between the proxy's MCP server surface and the upstream clients. Every
tool result and resource read is labelled at ingestion; every outgoing call has
its handle tokens resolved, its labels checked by the policy engine, and its
output labelled with the join of everything that influenced it.
"""

from __future__ import annotations

import json
import logging
import secrets
from collections.abc import Awaitable, Callable
from typing import Any

import mcp_types as types

from ..config import Delivery
from ..audit import AuditLog, fingerprint
from ..sandbox import sanitize_html
from .labels import TRUSTED, Integrity, Label
from .policy import PolicyEngine, PolicyViolation
from .store import HANDLE_RE, TaintedValue, TaintStore, UnknownHandleError

audit = logging.getLogger("vajra.audit")

InvokeTool = Callable[[dict[str, Any]], Awaitable[types.CallToolResult]]
ReadResource = Callable[[], Awaitable[types.ReadResourceResult]]
EventSink = Callable[[dict[str, Any]], None]
"""Receives structured decision events (for dashboards/demos). Operator-facing: may include untrusted previews."""

PREVIEW_CHARS = 4000


class TaintMiddleware:
    def __init__(
        self,
        policy: PolicyEngine,
        delivery: Delivery = Delivery.OPAQUE,
        store: TaintStore | None = None,
        on_event: EventSink | None = None,
        trail: AuditLog | None = None,
        session: str | None = None,
    ):
        self.policy = policy
        self.delivery = delivery
        self.store = store if store is not None else TaintStore()
        self.on_event = on_event
        self.trail = trail
        """Tamper-evident audit trail (metadata only; never untrusted content)."""
        self.session = session or secrets.token_hex(4)
        self.context: Label = TRUSTED
        """Label of everything the planner has observed. Monotone: it only ever rises."""
        self.withheld: list[dict[str, Any]] = []
        self.blocked: list[dict[str, Any]] = []
        self.burned: list[dict[str, Any]] = []

    async def call_tool(
        self, upstream: str, tool: str, arguments: dict[str, Any] | None, invoke: InvokeTool
    ) -> types.CallToolResult:
        qualified = f"{upstream}/{tool}"
        arg_labels: dict[str, Label] = {}
        try:
            resolved, arg_labels = self.store.resolve_arguments(arguments)
            self._emit(
                "resolve",
                tool=qualified,
                handles=sorted(set(HANDLE_RE.findall(json.dumps(arguments or {})))),
                arg_labels={k: l.integrity.name.lower() for k, l in arg_labels.items()},
                context=self.context.integrity.name.lower(),
            )
            self.policy.check_call(upstream, tool, arg_labels, self.context)
        except (PolicyViolation, UnknownHandleError) as e:
            audit.warning("BLOCK tool=%s reason=%s", qualified, e)
            self._emit("block", tool=qualified, reason=str(e))
            self.blocked.append({"tool": qualified, "reason": str(e)})
            self._audit("block", tool=qualified, reason=str(e), arg_labels=_labels(arg_labels))
            return _blocked(str(e))

        call_id = secrets.token_hex(4)
        audit.info(
            "CALL tool=%s call=%s args={%s}",
            qualified,
            call_id,
            ", ".join(f"{k}: {l.integrity.name.lower()}" for k, l in arg_labels.items()),
        )
        self._emit("allow", tool=qualified, call_id=call_id, resolved_arguments=resolved)
        self._audit("call", tool=qualified, call_id=call_id, arg_labels=_labels(arg_labels))
        result = await invoke(resolved)
        label = self.policy.tool_output_label(upstream, tool, call_id, arg_labels, self.context)
        rendered = _render_content(result.content)
        if self.policy.sanitizer(upstream, tool) == "html":
            rendered, burned = sanitize_html(rendered)
            # The cleaned text replaces the raw output everywhere downstream (labels, handles, reader).
            result = types.CallToolResult(content=[types.TextContent(text=rendered)], is_error=result.is_error)
            for b in burned:
                self.burned.append({"tool": qualified, "kind": b.kind, "preview": b.preview})
            audit.info("SANDBOX tool=%s call=%s burned=%d", qualified, call_id, len(burned))
            self._emit("sanitize", tool=qualified, call_id=call_id, burned=[{"kind": b.kind, "preview": b.preview} for b in burned],
                       kept_chars=len(rendered))
            if burned:
                # Fingerprints only: the removed text may be attacker-written and is never stored.
                self._audit("sanitize", tool=qualified, call_id=call_id, kept_chars=len(rendered),
                            removed=[{"kind": b.kind, "fingerprint": fingerprint(b.preview)} for b in burned])
        self._emit(
            "label",
            tool=qualified,
            call_id=call_id,
            label=label.describe(),
            trusted=label.trusted,
            preview=rendered[:PREVIEW_CHARS],
        )

        if label.trusted:
            self._emit("pass", tool=qualified, call_id=call_id)
            return result
        if self.delivery is Delivery.INLINE:
            self._taint_context(label)
            return result

        value = self.store.put(label, rendered, structured=result.structured_content)
        audit.info("WITHHOLD tool=%s call=%s handle=%s label=%s", qualified, call_id, value.handle, label.describe())
        self._emit("withhold", tool=qualified, call_id=call_id, handle=value.token, chars=len(value.text))
        self._audit("withhold", tool=qualified, call_id=call_id, handle=value.handle, chars=len(value.text),
                    sources=sorted(str(s) for s in label.sources))
        self.withheld.append({
            "tool": qualified,
            # Only planner-written (trusted) arguments are echoed: untrusted ones may hold attacker text.
            "args": {k: _short(v) for k, v in (arguments or {}).items() if arg_labels[k].trusted},
            "chars": len(value.text),
            "handle": value.token,
            # "external" = fresh outside content; otherwise it is derived from data that was already withheld.
            "external": self.policy.output_integrity(upstream, tool) is not Integrity.TRUSTED
            and all(l.trusted for l in arg_labels.values()),
        })
        return types.CallToolResult(content=[types.TextContent(text=_handle_notice(value))], is_error=result.is_error)

    async def read_resource(self, upstream: str, uri: str, invoke: ReadResource) -> types.ReadResourceResult:
        # Resource errors surface as MCP protocol errors; there is no is_error result to return here.
        self.policy.check_resource_read(upstream, uri, self.context)
        result = await invoke()
        label = self.policy.resource_output_label(upstream, uri, self.context)

        if label.trusted:
            return result
        if self.delivery is Delivery.INLINE:
            self._taint_context(label)
            return result

        mime = next((c.mime_type for c in result.contents if c.mime_type), None)
        value = self.store.put(label, _render_resource(result.contents), mime_type=mime)
        audit.info("WITHHOLD resource=%s/%s handle=%s label=%s", upstream, uri, value.handle, label.describe())
        self.withheld.append(
            {"tool": f"{upstream}/resource", "args": {"uri": uri}, "chars": len(value.text), "handle": value.token, "external": True}
        )
        return types.ReadResourceResult(
            contents=[types.TextResourceContents(uri=uri, mime_type="text/plain", text=_handle_notice(value))]
        )

    def security_report(self) -> dict[str, Any]:
        """What VAJRA did for this session, for showing to the human user."""
        return {
            "withheld": list(self.withheld),
            "blocked": list(self.blocked),
            "context_tainted": not self.context.trusted,
            "burned": list(self.burned),
            "notice": security_notice(self.withheld, self.blocked, not self.context.trusted, self.burned),
        }

    def withholds(self, output: Integrity) -> bool:
        """Whether output of this integrity is replaced by a handle (so an output schema can't be honoured)."""
        return self.delivery is Delivery.OPAQUE and output is not Integrity.TRUSTED

    def _taint_context(self, label: Label) -> None:
        if self.context.trusted:
            audit.warning("TAINT planner context now untrusted via %s", label.describe())
            self._emit("taint_context", label=label.describe())
            self._audit("taint_context", sources=sorted(str(x) for x in label.sources))
        self.context = self.context | label

    def _audit(self, kind: str, **fields: Any) -> None:
        if self.trail is not None:
            self.trail.record(kind, session=self.session, **fields)

    def _emit(self, kind: str, **fields: Any) -> None:
        if self.on_event is not None:
            self.on_event({"type": f"proxy.{kind}", **fields})


def security_notice(
    withheld: list[dict[str, Any]], blocked: list[dict[str, Any]], context_tainted: bool, burned: list[dict[str, Any]] | None = None
) -> str:
    """Plain-language summary for the user. It states what was withheld and blocked. It never claims an
    injection was "detected": VAJRA does not inspect content, it contains it."""
    lines: list[str] = []
    if burned:
        lines.append(f"VAJRA's sandbox burned {len(burned)} hidden part(s) of the content (things a person could not see):")
        lines.extend(f"  - {b['tool']}: {b['kind']}" for b in burned)
    external = [w for w in withheld if w["external"]]
    derived = len(withheld) - len(external)
    if external:
        lines.append("VAJRA withheld untrusted content from the agent's planner:")
        for w in external:
            args = ", ".join(f"{k}={v}" for k, v in w["args"].items())
            lines.append(f"  - {w['tool']}({args}): {w['chars']} chars from an outside source")
        lines.append(
            "  The planner never saw this content, so any instructions hidden in it could not steer the agent's actions."
        )
        if derived:
            lines.append(f"  {derived} result(s) derived from it (summaries, confirmations) also stayed untrusted.")
    if blocked:
        lines.append(f"VAJRA blocked {len(blocked)} action(s):")
        lines.extend(f"  - {b['reason']}" for b in blocked)
        lines.append("  Nothing was executed. If you intended this action, confirm the details (e.g. the recipient) yourself.")
    if context_tainted:
        lines.append("The planner was shown untrusted content directly, so further actions were restricted for this session.")
    return "\n".join(lines) if lines else "VAJRA: no untrusted content was involved in this request."


def _labels(arg_labels: Any) -> dict[str, str] | None:
    return {k: l.integrity.name.lower() for k, l in arg_labels.items()} if arg_labels else None


def _short(value: Any, limit: int = 80) -> str:
    s = value if isinstance(value, str) else json.dumps(value)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _blocked(reason: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=f"[vajra] call blocked: {reason}")], is_error=True)


def _handle_notice(value: TaintedValue) -> str:
    sources = ", ".join(sorted(str(s) for s in value.label.sources))
    return (
        "[vajra] untrusted data withheld from planner\n"
        f"handle: {value.token}\n"
        f"source: {sources}\n"
        f"length: {len(value.text)} chars\n"
        "You cannot read this data. To use it, pass the handle token as (part of) a tool argument."
    )


def _render_content(blocks: list[types.ContentBlock]) -> str:
    parts: list[str] = []
    for block in blocks:
        match block:
            case types.TextContent(text=text):
                parts.append(text)
            case types.EmbeddedResource(resource=types.TextResourceContents(text=text)):
                parts.append(text)
            case types.ResourceLink(uri=uri):
                parts.append(uri)
            case _:
                parts.append(f"[{block.type}]")
    return "\n".join(parts)


def _render_resource(contents: list[types.TextResourceContents | types.BlobResourceContents]) -> str:
    return "\n".join(c.text if isinstance(c, types.TextResourceContents) else f"[blob {c.mime_type or ''}]" for c in contents)
