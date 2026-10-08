"""Connections to upstream MCP servers."""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Self

import mcp_types as types
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

from ..config import NAMESPACE_SEP, UpstreamConfig

log = logging.getLogger("vajra.upstream")


@dataclass
class Upstream:
    config: UpstreamConfig
    client: Client
    tools: dict[str, types.Tool] = field(default_factory=dict)
    resources: dict[str, types.Resource] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.config.name


class UnknownRouteError(LookupError):
    pass


class UpstreamManager:
    """Owns one client session per configured upstream and routes calls to them."""

    def __init__(self, configs: dict[str, UpstreamConfig]) -> None:
        self._configs = configs
        self._stack = AsyncExitStack()
        self.upstreams: dict[str, Upstream] = {}
        self._resource_routes: dict[str, str] = {}

    async def __aenter__(self) -> Self:
        await self._stack.__aenter__()
        try:
            for cfg in self._configs.values():
                await self._connect(cfg)
        except BaseException:
            await self._stack.aclose()
            raise
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._stack.__aexit__(*exc)

    async def _connect(self, cfg: UpstreamConfig) -> None:
        params = StdioServerParameters(command=cfg.command, args=list(cfg.args), env=cfg.env, cwd=cfg.cwd)
        client = await self._stack.enter_async_context(Client(params))
        upstream = Upstream(cfg, client)

        for tool in await _list_all_tools(client):
            upstream.tools[tool.name] = tool
        if client.server_capabilities.resources is not None:
            for res in await _list_all_resources(client):
                upstream.resources[res.uri] = res
                if self._resource_routes.setdefault(res.uri, cfg.name) != cfg.name:
                    log.warning("resource %s exposed by multiple upstreams; routing to %s", res.uri, self._resource_routes[res.uri])

        self.upstreams[cfg.name] = upstream
        log.info("connected upstream %s: %d tools, %d resources", cfg.name, len(upstream.tools), len(upstream.resources))

    def route_tool(self, exposed_name: str) -> tuple[Upstream, str]:
        upstream_name, sep, tool = exposed_name.partition(NAMESPACE_SEP)
        upstream = self.upstreams.get(upstream_name)
        if not sep or upstream is None or tool not in upstream.tools or upstream.config.tool(tool).hidden:
            raise UnknownRouteError(f"unknown tool {exposed_name!r}")
        return upstream, tool

    def route_resource(self, uri: str) -> Upstream:
        try:
            return self.upstreams[self._resource_routes[uri]]
        except KeyError:
            raise UnknownRouteError(f"unknown resource {uri!r}") from None


def exposed_tool_name(upstream: str, tool: str) -> str:
    return f"{upstream}{NAMESPACE_SEP}{tool}"


async def _list_all_tools(client: Client) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools.extend(page.tools)
        if not (cursor := page.next_cursor):
            return tools


async def _list_all_resources(client: Client) -> list[types.Resource]:
    resources: list[types.Resource] = []
    cursor: str | None = None
    while True:
        page = await client.list_resources(cursor=cursor)
        resources.extend(page.resources)
        if not (cursor := page.next_cursor):
            return resources
