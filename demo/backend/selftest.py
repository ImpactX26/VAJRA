"""Live self-test: one deterministic check per threat VAJRA defends against.

Every check drives the real code paths (policy engine, middleware, admission
sandbox, content sandbox) with harmless synthetic data. Upstream servers are
replaced by stand-in functions, so the test needs no network, no LLM and no
attack text, and gives the same answer every time.
"""

from __future__ import annotations

import dataclasses
import tempfile
import time
from pathlib import Path
from typing import Any

import mcp_types as types

from vajra.config import ToolConfig, UpstreamConfig, VajraConfig
from vajra.sandbox import inspect_tool, sanitize_html
from vajra.taint.middleware import TaintMiddleware
from vajra.taint.policy import PolicyEngine
from vajra.taint.store import HANDLE_RE

from .runner import upstream_configs

SAFE_RECIPIENT = "alice@corp.example"


def _config() -> VajraConfig:
    """The demo's own policy, plus two rules the demo servers have no use for (lateral, database)."""
    with tempfile.TemporaryDirectory() as tmp:
        ups = upstream_configs(Path(tmp) / "outbox.jsonl")
    mail = ups["mail"]
    send = dataclasses.replace(mail.tool("send_email"), accepts_from={"body": frozenset({"files"})})
    ups["mail"] = dataclasses.replace(mail, tools={**mail.tools, "send_email": send})
    ups["db"] = UpstreamConfig("db", "unused", tools={"lookup_order": ToolConfig(arg_patterns={"order_id": r"[0-9]{1,10}"})})
    return VajraConfig(upstreams=ups)


class _Stub:
    """Stands in for an upstream tool: returns fixed text and records whether it was ever run."""

    def __init__(self, text: str = "ok") -> None:
        self.text, self.ran = text, False

    async def __call__(self, args: dict[str, Any]) -> types.CallToolResult:
        self.ran = True
        return types.CallToolResult(content=[types.TextContent(text=self.text)])


def _text(result: types.CallToolResult) -> str:
    return "".join(b.text for b in result.content if isinstance(b, types.TextContent))


def _handle(result: types.CallToolResult) -> str:
    m = HANDLE_RE.search(_text(result))
    return m.group(0) if m else ""


def _tool(name: str, description: str) -> types.Tool:
    return types.Tool(name=name, description=description, input_schema={"type": "object", "properties": {}})


def _check(name: str, ok: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail}


async def _indirect(cfg: VajraConfig) -> list[dict[str, Any]]:
    mw = TaintMiddleware(PolicyEngine(cfg))
    page = "<p>Opening hours: 9 to 5.</p><div style='display:none'>hidden note</div><!-- comment -->"
    fetched = await mw.call_tool("web", "fetch_url", {"url": "http://example.test"}, _Stub(page))
    handle = _handle(fetched)
    stored = mw.store.get(HANDLE_RE.match(handle).group(1)).text if handle else ""
    mail = _Stub()
    sent = await mw.call_tool("mail", "send_email", {"to": handle, "subject": "hi", "body": "hello"}, mail)
    return [
        _check("Planner receives a handle, not the page", bool(handle) and "Opening hours" not in _text(fetched),
               f"planner saw: {_text(fetched).splitlines()[0]}"),
        _check("Hidden parts burned in the content sandbox", len(mw.burned) == 2 and "hidden note" not in stored,
               f"{len(mw.burned)} part(s) burned: {', '.join(b['kind'] for b in mw.burned)}"),
        _check("Outside data cannot choose the recipient", sent.is_error and not mail.ran,
               "send_email blocked, never executed" if not mail.ran else "send_email ran"),
    ]


async def _poisoning(cfg: VajraConfig) -> list[dict[str, Any]]:
    clean = inspect_tool(_tool("convert_currency", "Convert an amount."), fingerprint="a", pin=None, taken=set())
    hidden = inspect_tool(_tool("summarize", "Summarize a page.​"), fingerprint="a", pin=None, taken=set())
    drift = inspect_tool(_tool("lookup", "Look up a record."), fingerprint="new", pin="reviewed", taken=set())
    return [
        _check("Ordinary tool is admitted", clean is None, "admitted" if clean is None else clean),
        _check("Invisible characters in a definition are rejected", hidden is not None, hidden or "admitted"),
        _check("Definition changed after review is rejected", drift is not None, drift or "admitted"),
    ]


async def _lateral(cfg: VajraConfig) -> list[dict[str, Any]]:
    shadow = inspect_tool(_tool("send_email", "Send an email."), fingerprint="a", pin=None, taken={"send_email"})
    mw = TaintMiddleware(PolicyEngine(cfg))
    web = _handle(await mw.call_tool("web", "fetch_url", {"url": "http://example.test"}, _Stub("page text")))
    doc = _handle(await mw.call_tool("files", "read_file", {"path": "notes/q3.txt"}, _Stub("quarterly notes")))
    from_web, from_files = _Stub(), _Stub()
    r1 = await mw.call_tool("mail", "send_email", {"to": SAFE_RECIPIENT, "subject": "s", "body": web}, from_web)
    await mw.call_tool("mail", "send_email", {"to": SAFE_RECIPIENT, "subject": "s", "body": doc}, from_files)
    return [
        _check("Second server reusing a tool name is rejected", shadow is not None, shadow or "admitted"),
        _check("Web data cannot cross into the mail tool", r1.is_error and not from_web.ran,
               mw.blocked[0]["reason"] if mw.blocked else "allowed"),
        _check("An allowed path still works (files to mail)", from_files.ran, "sent" if from_files.ran else "blocked"),
    ]


async def _exfiltration(cfg: VajraConfig) -> list[dict[str, Any]]:
    mw = TaintMiddleware(PolicyEngine(cfg))
    h = _handle(await mw.call_tool("files", "read_file", {"path": "secrets/keys.txt"}, _Stub("demo-value")))
    secret = mw.store.get(HANDLE_RE.match(h).group(1))
    plain = _handle(await mw.call_tool("files", "read_file", {"path": "notes/q3.txt"}, _Stub("notes")))
    leak, ok = _Stub(), _Stub()
    await mw.call_tool("mail", "send_email", {"to": SAFE_RECIPIENT, "subject": "s", "body": h}, leak)
    await mw.call_tool("mail", "send_email", {"to": SAFE_RECIPIENT, "subject": "s", "body": plain}, ok)
    return [
        _check("File under secrets/ is labelled secret", secret.label.secret, secret.label.describe()),
        _check("Secret data cannot leave by email", not leak.ran, mw.blocked[0]["reason"] if mw.blocked else "sent"),
        _check("Non-secret file can still be emailed", ok.ran, "sent" if ok.ran else "blocked"),
    ]


async def _downstream(cfg: VajraConfig) -> list[dict[str, Any]]:
    policy = PolicyEngine(cfg)

    def verdict(upstream: str, tool: str, args: dict[str, Any]) -> str | None:
        try:
            policy.check_values(upstream, tool, args)
            return None
        except Exception as e:  # PolicyViolation
            return str(e)

    good_id = verdict("db", "lookup_order", {"order_id": "42"})
    bad_id = verdict("db", "lookup_order", {"order_id": "42 OR 1=1"})
    good_to = verdict("mail", "send_email", {"to": SAFE_RECIPIENT})
    bad_to = verdict("mail", "send_email", {"to": SAFE_RECIPIENT + ", someone@elsewhere.test"})
    return [
        _check("A plain order number passes", good_id is None, "allowed" if good_id is None else good_id),
        _check("Query syntax inside an order number is refused", bad_id is not None, bad_id or "allowed"),
        _check("A single in-domain recipient passes", good_to is None, "allowed" if good_to is None else good_to),
        _check("Extra recipients smuggled into one field are refused", bad_to is not None, bad_to or "allowed"),
    ]


THREATS = [
    ("indirect", "Indirect prompt injection", "Content handling: opaque handles, quarantined reader, content sandbox", _indirect),
    ("poisoning", "MCP tool poisoning", "Tool admission sandbox and review pins", _poisoning),
    ("lateral", "Cross-tool shadowing and lateral movement", "Unique tool names and per-argument source rules", _lateral),
    ("exfiltration", "Data exfiltration", "Confidentiality labels on egress tools", _exfiltration),
    ("downstream", "Downstream command and SQL injection", "Argument grammar checked after handles are resolved", _downstream),
]


async def run_selftest() -> dict[str, Any]:
    cfg = _config()
    started = time.perf_counter()
    out = []
    for tid, title, layer, fn in THREATS:
        try:
            checks = await fn(cfg)
        except Exception as e:  # a crash is a failure, shown rather than hidden
            checks = [_check("Self-test ran", False, f"{type(e).__name__}: {e}")]
        out.append({"id": tid, "title": title, "layer": layer, "ok": all(c["ok"] for c in checks), "checks": checks})
    return {"ok": all(t["ok"] for t in out), "threats": out, "ms": round((time.perf_counter() - started) * 1000)}
