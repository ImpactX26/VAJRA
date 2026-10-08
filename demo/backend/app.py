"""Demo API: scenario metadata plus a live event stream of each run (Server-Sent Events)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .llm import DEFAULT_GROQ_MODEL as GROQ_MODEL
from .runner import MOCK_SERVERS, run_scenario, upstream_configs
from .scenarios import SCENARIOS

ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIST = ROOT / "demo" / "frontend" / "dist"
log = logging.getLogger("vajra.demo")
RESULT_FILES = ["evaluation_groq_agentdojo", "evaluation_groq", "evaluation_offline"]


def load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines); real environment variables win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def groq_settings() -> dict[str, str] | None:
    # The demo is pinned to one model so every run, live or recorded, is comparable.
    key = os.environ.get("GROQ_API_KEY", "").strip()
    return {"api_key": key, "model": GROQ_MODEL} if key else None


async def status(request: Request) -> JSONResponse:
    groq = groq_settings()
    return JSONResponse({"groq_available": groq is not None, "groq_model": GROQ_MODEL})


# The operator reviewed toolbox/lookup_record earlier and pinned that version; the server has changed it since.
REVIEWED_PIN = "sha256:6f1d0c2a9b7e4f3a8c5d2e1b0a9f8e7d"


async def sandbox(request: Request) -> JSONResponse:
    """Import every demo server's tools through VAJRA's sandbox and report each verdict."""
    import sys
    import tempfile

    from vajra.config import ToolConfig, UpstreamConfig
    from vajra.proxy import UpstreamManager

    with tempfile.TemporaryDirectory(prefix="vajra-sbx-api-") as tmp:
        configs = upstream_configs(Path(tmp) / "outbox.jsonl")
        configs["toolbox"] = UpstreamConfig(
            "toolbox", sys.executable, args=(MOCK_SERVERS, "--role", "toolbox"),
            tools={"lookup_record": ToolConfig(pin=REVIEWED_PIN)},
        )
        async with UpstreamManager(configs, sandbox=True) as upstreams:
            report = [
                {"server": a.server, "tool": a.tool, "admitted": a.admitted, "reason": a.reason, "fingerprint": a.fingerprint}
                for a in upstreams.admissions
            ]
            isolation = {n: u.isolation for n, u in upstreams.upstreams.items()}
    return JSONResponse({"servers": list(configs), "tools": report, "isolation": isolation})


async def isolation(request: Request) -> JSONResponse:
    """Run a deliberately misbehaving server with and without VAJRA's OS sandbox."""
    import sys

    import mcp_types as types

    from vajra.config import UpstreamConfig
    from vajra.proxy import UpstreamManager

    def text(r: types.CallToolResult) -> str:
        return "".join(b.text for b in r.content if isinstance(b, types.TextContent))

    out = []
    for mode in ("none", "auto"):
        cfg = {"probe": UpstreamConfig("probe", sys.executable, args=(MOCK_SERVERS, "--role", "probe"))}
        async with UpstreamManager(cfg, isolation=mode) as ups:
            up = ups.upstreams["probe"]
            out.append({
                "sandbox": mode != "none",
                "isolation": up.isolation,
                "start_program": text(await up.client.call_tool("start_program", {})),
                "grab_memory": text(await up.client.call_tool("grab_memory", {"megabytes": 512})),
            })
    return JSONResponse(out)


async def results(request: Request) -> JSONResponse:
    """Recorded evaluation runs (written by python -m demo.eval)."""
    out = []
    for stem in RESULT_FILES:
        path = ROOT / "docs" / f"{stem}.json"
        if path.is_file():
            out.append({"id": stem, **json.loads(path.read_text(encoding="utf-8"))})
    return JSONResponse(out)


async def scenarios(request: Request) -> JSONResponse:
    return JSONResponse([s.public() for s in SCENARIOS.values()])


SITE_URL = "http://127.0.0.1:8090/setup"
URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def live_scenario(prompt: str) -> Any:
    """A user-typed request against the local demo website (localhost only)."""
    m = URL_RE.search(prompt)
    url = m.group(0).rstrip(".,)") if m else None
    if not prompt.strip() or not url or urlparse(url).hostname not in ("127.0.0.1", "localhost"):
        return None
    base = SCENARIOS["malicious-webpage"]
    return dataclasses.replace(
        base,
        id="live",
        title="Live web fetch",
        task=prompt.strip(),
        files=["mock_web/setup_guide.html"],
        source_args={"url": url},
        goal="answer_user",
        expectation={},
    )


async def site(request: Request) -> JSONResponse:
    """Is the separate demo website reachable?"""
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            up = (await client.get(SITE_URL)).status_code == 200
    except httpx.HTTPError:
        up = False
    return JSONResponse({"url": SITE_URL, "up": up})


async def run(request: Request) -> Any:
    q = request.query_params
    scenario = live_scenario(q.get("prompt", "")) if q.get("scenario") == "live" else SCENARIOS.get(q.get("scenario", ""))
    mode = q.get("mode")
    provider = q.get("provider", "scripted")
    if scenario is None or mode not in ("unprotected", "protected") or provider not in ("groq", "scripted"):
        return JSONResponse({"error": "bad scenario/mode/provider"}, status_code=400)

    groq = groq_settings()

    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    async def worker() -> None:
        try:
            await run_scenario(scenario, mode, provider, queue.put_nowait, groq)
        except Exception as e:  # surfaced to the UI instead of a silently dead stream
            log.exception("run failed")
            while isinstance(e, BaseExceptionGroup) and e.exceptions:
                e = e.exceptions[0]  # anyio task groups wrap the real cause
            queue.put_nowait({"type": "error", "message": f"{type(e).__name__}: {e}"})
        finally:
            queue.put_nowait(None)

    async def stream():
        task = asyncio.create_task(worker())
        try:
            while (event := await queue.get()) is not None:
                yield {"data": json.dumps(event, default=str)}
            yield {"data": json.dumps({"type": "done"})}
        finally:
            task.cancel()

    return EventSourceResponse(stream())


def create_app() -> Starlette:
    load_dotenv(ROOT / ".env")
    routes: list[Any] = [
        Route("/api/status", status),
        Route("/api/scenarios", scenarios),
        Route("/api/results", results),
        Route("/api/sandbox", sandbox),
        Route("/api/site", site),
        Route("/api/isolation", isolation),
        Route("/api/run", run),
    ]
    if FRONTEND_DIST.is_dir():
        routes.append(Mount("/", StaticFiles(directory=FRONTEND_DIST, html=True)))
    return Starlette(routes=routes)
