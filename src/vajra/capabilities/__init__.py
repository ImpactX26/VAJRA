"""Capability tokens (not yet implemented).

Plan: every upstream tool call must present a scoped, unforgeable token minted
by the proxy from *trusted* intent (the user's request / planner plan), binding
tool name + argument constraints + expiry. A token whose minting inputs carry
an untrusted label is minted with zero privilege. Enforcement hooks in at
``PolicyEngine.check_call``, alongside the existing label checks.
"""
