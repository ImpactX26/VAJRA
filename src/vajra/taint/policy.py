"""Deterministic flow policy.

Two rules, both pure functions of labels and operator config:

1. **Data flow** — an argument whose (label ⊔ context) is untrusted may only
   reach a tool parameter the operator listed in ``untrusted_args``.
2. **Control flow** — once the planner context itself is tainted, the *choice*
   to call a tool is attacker-influenced, so only tools marked
   ``allow_tainted_invocation`` may be called at all.

Capability tokens (see ``vajra.capabilities``) will layer on top of this.
"""

from __future__ import annotations

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

    def output_integrity(self, upstream: str, tool: str) -> Integrity:
        """The configured integrity of a tool's own output, before joining in its inputs."""
        return self._config.upstreams[upstream].tool_output(tool)

    def tool_output_label(
        self, upstream: str, tool: str, call_id: str, arg_labels: Mapping[str, Label], context: Label
    ) -> Label:
        """Output integrity is the join of the tool's own trust and everything that influenced the call."""
        integrity = self._config.upstreams[upstream].tool_output(tool)
        base = Label(integrity, frozenset({Source(upstream, "tool", tool, call_id)}))
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
