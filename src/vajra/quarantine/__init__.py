"""Dual-LLM quarantine.

A reader model processes untrusted data on the planner's behalf. It is handed
plain text and returns plain text: there is no tool schema anywhere in its
interface, so even a fully hijacked reader cannot act. Its output is labelled
with the join of its inputs by the ordinary taint middleware, so extraction
never launders taint — the planner gets back another handle.
"""

from .reader import QUARANTINE_TOOL_NAME, QuarantinedReader, quarantine_tool, with_quarantine

__all__ = ["QUARANTINE_TOOL_NAME", "QuarantinedReader", "quarantine_tool", "with_quarantine"]
