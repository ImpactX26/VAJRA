"""The audit trail is tamper-evident and never stores attacker-controlled text."""

import json
import sys
from pathlib import Path

from vajra.audit import AuditLog
from vajra.config import Delivery, ToolConfig, UpstreamConfig, VajraConfig
from vajra.proxy import UpstreamManager, build_server
from vajra.taint.middleware import TaintMiddleware
from vajra.taint.policy import PolicyEngine

FAKE = str(Path(__file__).parent / "fixtures" / "fake_upstream.py")
INJECTION_MARKER = "IGNORE ALL PREVIOUS"


def test_chain_verifies_and_detects_edits(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.record("call", tool=f"files/read_file", n=i)
    assert log.verify()["ok"] and AuditLog(path).verify()["ok"]  # survives a reload

    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["tool"] = "mail/send_email"  # an attacker rewrites history
    lines[2] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = AuditLog(path).verify()
    assert not result["ok"] and result["broken_at"] == 2 and "modified" in result["reason"]


def test_deleting_a_record_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.record("block", tool="mail/send_email", n=i)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert AuditLog(path).verify()["broken_at"] == 1


async def test_proxy_decisions_are_audited_without_attacker_text():
    from mcp.client import Client

    trail = AuditLog()
    mail = UpstreamConfig("mail", sys.executable, args=(FAKE,), tools={"send_email": ToolConfig(untrusted_args=frozenset({"body"}))})
    config = VajraConfig(delivery=Delivery.OPAQUE, upstreams={"mail": mail})
    middleware = TaintMiddleware(PolicyEngine(config), trail=trail, session="t1")
    async with UpstreamManager(config.upstreams, trail=trail) as upstreams:
        async with Client(build_server("vajra", upstreams, middleware)) as planner:
            inbox = await planner.call_tool("mail__read_inbox", {})
            token = inbox.content[0].text.split("handle: ")[1].split()[0]
            await planner.call_tool("mail__send_email", {"to": token, "subject": "x", "body": "x"})

    kinds = [r["kind"] for r in trail.tail()]
    assert {"isolate", "tool.admit", "call", "withhold", "block"} <= set(kinds)
    dump = json.dumps(trail.tail())
    assert INJECTION_MARKER not in dump  # metadata only, never the untrusted content
    assert trail.verify()["ok"]
