"""Run VAJRA as a stdio MCP server: ``python -m vajra --config vajra.toml``."""

from __future__ import annotations

import argparse
import logging

import anyio
from mcp.server.stdio import stdio_server

from .config import load_config
from .proxy import UpstreamManager, build_server
from .taint.middleware import TaintMiddleware
from .taint.policy import PolicyEngine


async def serve(config_path: str) -> None:
    config = load_config(config_path)
    middleware = TaintMiddleware(PolicyEngine(config), delivery=config.delivery)
    async with UpstreamManager(config.upstreams) as upstreams:
        server = build_server(config.name, upstreams, middleware)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(prog="vajra", description=__doc__)
    parser.add_argument("--config", default="vajra.toml")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    # stdout carries the MCP protocol; logs must go to stderr (logging's default).
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    anyio.run(serve, args.config)


if __name__ == "__main__":
    main()
