"""Demo API: scenario metadata plus a live event stream of each run (Server-Sent Events)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .llm import DEFAULT_GROQ_MODEL as GROQ_MODEL
from .runner import run_scenario
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


async def run(request: Request) -> Any:
    q = request.query_params
    scenario = SCENARIOS.get(q.get("scenario", ""))
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
        Route("/api/run", run),
    ]
    if FRONTEND_DIST.is_dir():
        routes.append(Mount("/", StaticFiles(directory=FRONTEND_DIST, html=True)))
    return Starlette(routes=routes)
