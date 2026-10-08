"""Demo API: scenario metadata plus a live event stream of each run (Server-Sent Events)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx
from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .llm import DEFAULT_GROQ_MODEL, GROQ_MODELS_URL
from .runner import run_scenario
from .scenarios import SCENARIOS

ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIST = ROOT / "demo" / "frontend" / "dist"
log = logging.getLogger("vajra.demo")
_NON_CHAT = ("whisper", "orpheus", "guard", "allam")
_models_cache: list[str] | None = None


def load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines); real environment variables win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def groq_settings() -> dict[str, str] | None:
    key = os.environ.get("GROQ_API_KEY", "").strip()
    return {"api_key": key, "model": os.environ.get("GROQ_MODEL", DEFAULT_GROQ_MODEL)} if key else None


async def groq_models(api_key: str) -> list[str]:
    """Chat models this key can use (cached). Falls back to the default model if the listing fails."""
    global _models_cache
    if _models_cache is None:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(GROQ_MODELS_URL, headers={"Authorization": f"Bearer {api_key}"})
                resp.raise_for_status()
            ids = sorted(m["id"] for m in resp.json()["data"] if m.get("active", True))
            _models_cache = [i for i in ids if not any(x in i for x in _NON_CHAT)]
        except (httpx.HTTPError, KeyError, ValueError):
            log.warning("could not list Groq models", exc_info=True)
            return [os.environ.get("GROQ_MODEL", DEFAULT_GROQ_MODEL)]
    return _models_cache


async def status(request: Request) -> JSONResponse:
    groq = groq_settings()
    if groq is None:
        return JSONResponse({"groq_available": False, "groq_model": None, "groq_models": []})
    models = await groq_models(groq["api_key"])
    if groq["model"] not in models:
        models = [groq["model"], *models]
    return JSONResponse({"groq_available": True, "groq_model": groq["model"], "groq_models": models})


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
    if groq and q.get("model"):
        if q["model"] not in await groq_models(groq["api_key"]) and q["model"] != groq["model"]:
            return JSONResponse({"error": "unknown model"}, status_code=400)
        groq["model"] = q["model"]

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
        Route("/api/run", run),
    ]
    if FRONTEND_DIST.is_dir():
        routes.append(Mount("/", StaticFiles(directory=FRONTEND_DIST, html=True)))
    return Starlette(routes=routes)
