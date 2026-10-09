"""Deterministic flow policy.

Two rules, both pure functions of labels and operator config:

1. **Data flow** — an argument whose (label ⊔ context) is untrusted may only
   reach a tool parameter the operator listed in ``untrusted_args``.
2. **Control flow** — once the planner context itself is tainted, the *choice*
   to call a tool is attacker-influenced, so only tools marked
   ``allow_tainted_invocation`` may be called at all.

Capability tokens (``vajra.capabilities``) and the action grammar (``vajra.grammar``) are enforced
alongside these rules by the middleware.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from ..config import VajraConfig
from .labels import Integrity, Label, Source, join_all


class PolicyViolation(Exception):
    pass


class PolicyEngine:
    def __init__(self, config: VajraConfig) -> None:
        self._config = config

    def check_call(self, upstream: str, tool: str, arg_labels: Mapping[str, Label], context: Label) -> None:
        cfg = self._config.upstreams[upstream].tool(tool)
        qualified = f"{upstream}/{tool}"

        if not context.trusted and not cfg.allow_tainted_invocation:
            raise PolicyViolation(
                f"{qualified}: planner context is tainted by {context.describe()}; "
                "tool is not allowed under tainted control flow"
            )
        for arg, label in arg_labels.items():
            effective = label | context
            if not effective.trusted and arg not in cfg.untrusted_args:
                raise PolicyViolation(
                    f"{qualified}: argument {arg!r} carries {effective.describe()} data; "
                    "this parameter only accepts trusted data"
                )
            # Lateral movement: untrusted data may only cross from servers this argument accepts.
            allowed = cfg.accepts_from.get(arg)
            if allowed is not None and not effective.trusted:
                foreign = sorted(effective.upstreams - allowed - {"vajra"})
                if foreign:
                    raise PolicyViolation(
                        f"{qualified}: argument {arg!r} carries data from {', '.join(foreign)}; "
                        f"this parameter only accepts outside data from {', '.join(sorted(allowed)) or 'no server'}"
                    )
            # Exfiltration: secret data never enters a tool that sends data out.
            if cfg.egress and effective.secret:
                raise PolicyViolation(
                    f"{qualified}: argument {arg!r} carries secret data; {qualified} sends data outside, "
                    "so secret data may not flow into it"
                )

    def check_values(self, upstream: str, tool: str, resolved: Mapping[str, object]) -> None:
        """Argument grammar: every constrained argument must fully match its pattern after handles are
        resolved, so downstream shells, queries and APIs only ever receive the expected shape."""
        cfg = self._config.upstreams[upstream].tool(tool)
        for arg, pattern in cfg.arg_patterns.items():
            if arg not in resolved:
                continue
            value = resolved[arg]
            if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
                raise PolicyViolation(
                    f"{upstream}/{tool}: argument {arg!r} does not match its allowed format"
                )

    def capability_spec(self, upstream: str, tool: str) -> dict[str, str]:
        """Arguments of a capability-gated tool and how they bind to the user's request (empty = not gated)."""
        return self._config.upstreams[upstream].tool(tool).capability

    def gated_tools(self) -> dict[str, dict[str, str]]:
        return {f"{u}/{t}": dict(c.capability) for u, up in self._config.upstreams.items() for t, c in up.tools.items() if c.capability}

    def sanitizer(self, upstream: str, tool: str) -> str | None:
        """Which content sandbox (if any) this tool's output goes through."""
        return self._config.upstreams[upstream].tool(tool).sanitize

    def output_integrity(self, upstream: str, tool: str) -> Integrity:
        """The configured integrity of a tool's own output, before joining in its inputs."""
        return self._config.upstreams[upstream].tool_output(tool)

    def tool_output_label(
        self,
        upstream: str,
        tool: str,
        call_id: str,
        arg_labels: Mapping[str, Label],
        context: Label,
        resolved: Mapping[str, object] | None = None,
    ) -> Label:
        """Output label = the tool's own trust and secrecy, joined with everything that influenced the call."""
        cfg = self._config.upstreams[upstream].tool(tool)
        integrity = self._config.upstreams[upstream].tool_output(tool)
        secret = any(
            isinstance((resolved or {}).get(arg), str) and re.search(pattern, resolved[arg]) is not None
            for arg, pattern in cfg.secret_when.items()
        )
        base = Label(integrity, frozenset({Source(upstream, "tool", tool, call_id)}), secret)
        return join_all([base, context, *arg_labels.values()])

    def check_resource_read(self, upstream: str, uri: str, context: Label) -> None:
        # A tainted planner choosing a URI is an exfiltration channel (e.g. data in a query string).
        if not context.trusted:
            raise PolicyViolation(
                f"{upstream}: resource read of {uri!r} refused; planner context is tainted by {context.describe()}"
            )

    def resource_output_label(self, upstream: str, uri: str, context: Label) -> Label:
        base = Label(self._config.upstreams[upstream].output, frozenset({Source(upstream, "resource", uri)}))
        return base | context
