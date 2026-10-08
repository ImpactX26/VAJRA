"""The MCP server surface the planner (client) connects to.

Every tool call and resource read is routed through ``TaintMiddleware``; the
proxy never forwards upstream data to the client by any other path. Upstream
prompts are deliberately not proxied: they are untrusted text that would land
directly in the planner's context.
"""

from __future__ import annotations

from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError

from ..quarantine.reader import NATIVE_UPSTREAM, QUARANTINE_TOOL, QUARANTINE_TOOL_NAME, QuarantinedReader, quarantine_tool
from ..taint.middleware import TaintMiddleware
from ..taint.policy import PolicyViolation
from .upstream import UnknownRouteError, UpstreamManager, exposed_tool_name


SERVER_INSTRUCTIONS = (
    "Untrusted tool output is withheld and replaced with a handle token ($vajra:h_...). "
    "You cannot read handle contents; pass the token as a tool argument to use the data. "
    "Calls that route untrusted data into a parameter that requires trusted data are blocked."
)


def build_server(
    name: str, upstreams: UpstreamManager, middleware: TaintMiddleware, reader: QuarantinedReader | None = None
) -> Server[Any]:
    """Build the proxy server. With ``reader``, also expose the quarantine tool (the policy engine must
    then be built from ``vajra.quarantine.with_quarantine(config)``)."""

    async def list_tools(ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        tools: list[types.Tool] = []
        for upstream in upstreams.upstreams.values():
            for tool in upstream.tools.values():
                cfg = upstream.config.tool(tool.name)
                if cfg.hidden:
                    continue
                update: dict[str, Any] = {"name": exposed_tool_name(upstream.name, tool.name)}
                if cfg.description is not None:
                    update["description"] = cfg.description
                if middleware.withholds(upstream.config.tool_output(tool.name)):
                    update["output_schema"] = None  # the planner receives a handle notice, not this schema
                tools.append(tool.model_copy(update=update))
        if reader is not None:
            tools.append(quarantine_tool())
        return types.ListToolsResult(tools=tools)

    async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        if reader is not None and params.name == QUARANTINE_TOOL_NAME:

            async def invoke_reader(arguments: dict[str, Any]) -> types.CallToolResult:
                output = await reader(str(arguments.get("data", "")), str(arguments.get("instruction", "")))
                return types.CallToolResult(content=[types.TextContent(text=output)])

            return await middleware.call_tool(NATIVE_UPSTREAM, QUARANTINE_TOOL, params.arguments, invoke_reader)

        try:
            upstream, tool = upstreams.route_tool(params.name)
        except UnknownRouteError as e:
            return types.CallToolResult(content=[types.TextContent(text=f"[vajra] {e}")], is_error=True)

        async def invoke(arguments: dict[str, Any]) -> types.CallToolResult:
            return await upstream.client.call_tool(tool, arguments)

        return await middleware.call_tool(upstream.name, tool, params.arguments, invoke)

    async def list_resources(ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListResourcesResult:
        return types.ListResourcesResult(
            resources=[r for u in upstreams.upstreams.values() for r in u.resources.values()]
        )

    async def read_resource(ctx: Any, params: types.ReadResourceRequestParams) -> types.ReadResourceResult:
        try:
            upstream = upstreams.route_resource(params.uri)
        except UnknownRouteError as e:
            raise MCPError(code=types.INVALID_PARAMS, message=str(e)) from None

        async def invoke() -> types.ReadResourceResult:
            return await upstream.client.read_resource(params.uri)

        try:
            return await middleware.read_resource(upstream.name, params.uri, invoke)
        except PolicyViolation as e:
            raise MCPError(code=types.INVALID_REQUEST, message=f"[vajra] {e}") from None

    return Server(
        name,
        instructions=SERVER_INSTRUCTIONS,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
        on_list_resources=list_resources,
        on_read_resource=read_resource,
    )
