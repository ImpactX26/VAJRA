"""End-to-end: planner client -> VAJRA (in-process) -> hostile upstream (stdio subprocess)."""

import re
import sys
from pathlib import Path

import mcp_types as types
import pytest
from mcp.client import Client
from mcp.shared.exceptions import MCPError

from vajra.config import Delivery, ToolConfig, UpstreamConfig, VajraConfig
from vajra.proxy import UpstreamManager, build_server
from vajra.taint.middleware import TaintMiddleware
from vajra.taint.policy import PolicyEngine

FAKE = str(Path(__file__).parent / "fixtures" / "fake_upstream.py")
TOKEN = re.compile(r"\$vajra:h_[0-9a-f]{32}")
INJECTION_MARKER = "IGNORE ALL PREVIOUS"


def make_config(delivery: Delivery) -> VajraConfig:
    mail = UpstreamConfig(
        "mail",
        sys.executable,
        args=(FAKE,),
        tools={
            "send_email": ToolConfig(untrusted_args=frozenset({"body"})),
            "add": ToolConfig(hidden=True),
        },
    )
    return VajraConfig(delivery=delivery, upstreams={"mail": mail})


async def run(delivery: Delivery, scenario):
    config = make_config(delivery)
    middleware = TaintMiddleware(PolicyEngine(config), delivery=delivery)
    async with UpstreamManager(config.upstreams) as upstreams:
        async with Client(build_server("vajra", upstreams, middleware)) as planner:
            await scenario(planner, middleware)


def text(result: types.CallToolResult) -> str:
    return "\n".join(b.text for b in result.content if isinstance(b, types.TextContent))


async def test_tools_are_namespaced_and_hidden_tools_dropped():
    async def scenario(planner, _):
        names = {t.name for t in (await planner.list_tools()).tools}
        assert names == {"mail__read_inbox", "mail__send_email"}

    await run(Delivery.OPAQUE, scenario)


async def test_planner_never_sees_injection_and_handle_flows_to_allowed_arg():
    async def scenario(planner, middleware):
        inbox = await planner.call_tool("mail__read_inbox", {})
        assert INJECTION_MARKER not in text(inbox)
        (token,) = TOKEN.findall(text(inbox))

        sent = await planner.call_tool(
            "mail__send_email", {"to": "me@corp.example", "subject": "fwd", "body": f"FYI: {token}"}
        )
        assert not sent.is_error
        # send_email's output was influenced by the handle, so it is withheld too.
        assert INJECTION_MARKER not in text(sent)
        (sent_token,) = TOKEN.findall(text(sent))
        echoed = middleware.store.get(sent_token.removeprefix("$vajra:"))
        assert "to=me@corp.example" in echoed.text and INJECTION_MARKER in echoed.text
        assert middleware.context.trusted

    await run(Delivery.OPAQUE, scenario)


async def test_untrusted_data_cannot_choose_recipient():
    async def scenario(planner, _):
        (token,) = TOKEN.findall(text(await planner.call_tool("mail__read_inbox", {})))
        blocked = await planner.call_tool("mail__send_email", {"to": token, "subject": "x", "body": "x"})
        assert blocked.is_error and "'to'" in text(blocked)

    await run(Delivery.OPAQUE, scenario)


async def test_forged_handle_is_rejected():
    async def scenario(planner, _):
        forged = "$vajra:h_" + "a" * 32
        blocked = await planner.call_tool("mail__send_email", {"to": "a@b.c", "subject": "x", "body": forged})
        assert blocked.is_error and "unknown handle" in text(blocked)

    await run(Delivery.OPAQUE, scenario)


async def test_resource_reads_are_withheld():
    async def scenario(planner, _):
        result = await planner.read_resource("inbox://latest")
        body = result.contents[0].text
        assert INJECTION_MARKER not in body and TOKEN.search(body)

    await run(Delivery.OPAQUE, scenario)


async def test_inline_delivery_taints_context_and_locks_down_actions():
    async def scenario(planner, middleware):
        inbox = await planner.call_tool("mail__read_inbox", {})
        assert INJECTION_MARKER in text(inbox)  # the planner saw it...
        assert not middleware.context.trusted  # ...so its context is now tainted

        blocked = await planner.call_tool("mail__send_email", {"to": "me@corp.example", "subject": "s", "body": "b"})
        assert blocked.is_error and "tainted" in text(blocked)
        with pytest.raises(MCPError):
            await planner.read_resource("inbox://latest")

    await run(Delivery.INLINE, scenario)


async def test_quarantine_reader_output_stays_tainted():
    from vajra.quarantine import QuarantinedReader, with_quarantine

    seen: list[str] = []

    async def fake_reader(system: str, user: str) -> str:
        seen.append(user)
        return "SUMMARY (reader obeyed nothing)"

    config = make_config(Delivery.OPAQUE)
    middleware = TaintMiddleware(PolicyEngine(with_quarantine(config)))
    async with UpstreamManager(config.upstreams) as upstreams:
        server = build_server("vajra", upstreams, middleware, QuarantinedReader(fake_reader))
        async with Client(server) as planner:
            assert "vajra__quarantine" in {t.name for t in (await planner.list_tools()).tools}
            (token,) = TOKEN.findall(text(await planner.call_tool("mail__read_inbox", {})))

            out = await planner.call_tool("vajra__quarantine", {"data": token, "instruction": "Summarize"})
            assert INJECTION_MARKER in seen[0]  # the reader got the real data...
            assert "SUMMARY" not in text(out)  # ...but its output is withheld from the planner
            (summary,) = TOKEN.findall(text(out))
            assert not middleware.store.get(summary.removeprefix("$vajra:")).label.trusted

            # A planner-chosen instruction must be trusted; untrusted data can't steer the reader's instruction.
            blocked = await planner.call_tool("vajra__quarantine", {"data": "x", "instruction": token})
            assert blocked.is_error and "'instruction'" in text(blocked)


async def test_tool_pins_reject_changed_definitions():
    from vajra.proxy.upstream import tool_fingerprint

    config = make_config(Delivery.OPAQUE)
    async with UpstreamManager(config.upstreams) as upstreams:
        real = tool_fingerprint(upstreams.upstreams["mail"].tools["read_inbox"])

    pinned = UpstreamConfig(
        "mail",
        sys.executable,
        args=(FAKE,),
        tools={
            "read_inbox": ToolConfig(pin=real),  # matches: kept
            "send_email": ToolConfig(pin="sha256:" + "0" * 32),  # e.g. description poisoned after review: dropped
        },
    )
    config = VajraConfig(upstreams={"mail": pinned})
    middleware = TaintMiddleware(PolicyEngine(config))
    async with UpstreamManager(config.upstreams) as upstreams:
        assert "send_email" in upstreams.upstreams["mail"].rejected
        async with Client(build_server("vajra", upstreams, middleware)) as planner:
            names = {t.name for t in (await planner.list_tools()).tools}
            assert "mail__read_inbox" in names and "mail__send_email" not in names
            blocked = await planner.call_tool("mail__send_email", {"to": "a@b.c", "subject": "s", "body": "b"})
            assert blocked.is_error


async def test_security_notice_reports_without_repeating_attacker_text():
    async def scenario(planner, middleware):
        (token,) = TOKEN.findall(text(await planner.call_tool("mail__read_inbox", {})))
        await planner.call_tool("mail__send_email", {"to": token, "subject": "x", "body": "x"})
        report = middleware.security_report()
        assert [w["tool"] for w in report["withheld"]] == ["mail/read_inbox"]
        assert len(report["blocked"]) == 1 and "'to'" in report["blocked"][0]["reason"]
        assert "withheld untrusted content" in report["notice"] and "blocked 1 action" in report["notice"]
        assert INJECTION_MARKER not in report["notice"]  # never echoes the attacker's text back
        assert "detected" not in report["notice"]  # VAJRA contains, it does not claim detection

    await run(Delivery.OPAQUE, scenario)
