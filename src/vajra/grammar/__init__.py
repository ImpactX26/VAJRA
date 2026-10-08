"""Constrained action grammar (not yet implemented).

Plan: the planner's tool calls are parsed against a strict DSL/JSON-schema
derived from operator-approved tool signatures before they reach
``TaintMiddleware``; anything that fails to parse is rejected, never repaired.
"""
