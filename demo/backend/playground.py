"""Interactive playgrounds for the How it works page: capability tokens and the action grammar.

Both use the real modules and the demo's real policy: the grammar is generated from the tools the
demo servers actually expose (after admission), the gated tools come from the demo configuration.
"""

from __future__ import annotations

import asyncio
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

from vajra.capabilities import CapabilityError, CapabilityWallet
from vajra.config import VajraConfig
from vajra.grammar import ActionGrammar, GrammarError
from vajra.proxy import UpstreamManager
from vajra.proxy.upstream import exposed_tool_name
from vajra.quarantine.reader import QUARANTINE_TOOL_NAME, quarantine_tool
from vajra.taint.policy import PolicyEngine

from .runner import upstream_configs

_grammar: ActionGrammar | None = None
_lock = asyncio.Lock()
_wallets: dict[str, tuple[float, CapabilityWallet]] = {}
WALLET_TTL = 30 * 60


def _gated() -> dict[str, dict[str, str]]:
    with tempfile.TemporaryDirectory() as tmp:
        return PolicyEngine(VajraConfig(upstreams=upstream_configs(Path(tmp) / "o.jsonl"))).gated_tools()


async def grammar() -> ActionGrammar:
    """Built once from the demo servers' admitted tools, plus the quarantine tool."""
    global _grammar
    async with _lock:
        if _grammar is None:
            with tempfile.TemporaryDirectory(prefix="vajra-grammar-") as tmp:
                async with UpstreamManager(upstream_configs(Path(tmp) / "o.jsonl"), isolation="none") as ups:
                    schemas = {exposed_tool_name(u.name, t.name): t.input_schema for u in ups.upstreams.values() for t in u.tools.values()}
            schemas[QUARANTINE_TOOL_NAME] = quarantine_tool().input_schema
            _grammar = ActionGrammar(schemas)
    return _grammar


async def grammar_info() -> dict[str, Any]:
    g = await grammar()
    return {"productions": g.ebnf(), "tools": sorted(g.tools)}


async def parse(text: str) -> dict[str, Any]:
    g = await grammar()
    try:
        a = g.parse(text)
        return {"ok": True, "tool": a.tool, "args": a.args}
    except GrammarError as e:
        return {"ok": False, "error": str(e), "position": e.position}


def mint(request: str) -> dict[str, Any]:
    now = time.time()
    for k in [k for k, (t, _) in _wallets.items() if now - t > WALLET_TTL]:
        del _wallets[k]
    wallet = CapabilityWallet()
    gated = _gated()
    wallet.mint_from_request(request, gated)
    sid = secrets.token_hex(8)
    _wallets[sid] = (now, wallet)
    return {"session": sid, "tokens": wallet.tokens(), "gated": gated}


def check(session: str, tool: str, args: dict[str, Any], token: str | None = None) -> dict[str, Any]:
    entry = _wallets.get(session)
    if entry is None:
        return {"ok": False, "reason": "session expired: mint tokens again"}
    wallet = entry[1]
    try:
        if token:
            cap = wallet.verify_token(token)
            return {"ok": True, "reason": f"signature valid: token {cap.id} was issued by VAJRA for {cap.tool}"}
        cap = wallet.check(tool, args, consume=False)
        return {"ok": True, "reason": f"covered by token {cap.id}"}
    except CapabilityError as e:
        return {"ok": False, "reason": str(e)}
