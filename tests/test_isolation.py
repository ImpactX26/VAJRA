"""The OS sandbox is real: a server that tries to exceed its limits is stopped by the kernel."""

import sys
from pathlib import Path

import mcp_types as types

from vajra.config import UpstreamConfig
from vajra.isolation import Limits
from vajra.proxy import UpstreamManager

PROBE = str(Path(__file__).parents[1] / "demo" / "backend" / "mock_servers.py")


def text(result: types.CallToolResult) -> str:
    return "".join(b.text for b in result.content if isinstance(b, types.TextContent))


async def probe(isolation: str) -> tuple[str, str, str]:
    cfg = {"probe": UpstreamConfig("probe", sys.executable, args=(PROBE, "--role", "probe"))}
    async with UpstreamManager(cfg, isolation=isolation, limits=Limits(memory_mb=256)) as ups:
        up = ups.upstreams["probe"]
        spawn = text(await up.client.call_tool("start_program", {}))
        memory = text(await up.client.call_tool("grab_memory", {"megabytes": 512}))
        return up.isolation, spawn, memory


async def test_jailed_server_cannot_start_programs_or_exceed_memory():
    isolation, spawn, memory = await probe("job")
    assert "256 MB" in isolation
    assert spawn.startswith("blocked"), spawn
    assert memory.startswith("blocked"), memory


async def test_without_isolation_the_same_server_can():
    isolation, spawn, memory = await probe("none")
    assert isolation == "no isolation"
    assert spawn.startswith("allowed") and memory.startswith("allowed")
