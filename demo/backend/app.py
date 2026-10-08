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
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .llm import DEFAULT_GROQ_MODEL as GROQ_MODEL
from . import winsandbox
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


async def winsandbox_state(request: Request) -> JSONResponse:
    return JSONResponse(await asyncio.to_thread(winsandbox.state))


async def winsandbox_start(request: Request) -> JSONResponse:
    """Boot a Windows Sandbox VM and start the web MCP server inside it (takes 1-3 minutes)."""
    return JSONResponse(await asyncio.to_thread(winsandbox.launch))


async def winsandbox_stop(request: Request) -> JSONResponse:
    return JSONResponse(await asyncio.to_thread(winsandbox.stop))


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


# ---------------------------------------------------------------- audit trail + monitoring
from contextlib import asynccontextmanager  # noqa: E402

from .audit_trail import TRAIL  # noqa: E402
from .monitor import SCANNER  # noqa: E402


async def audit_list(request: Request) -> JSONResponse:
    q = request.query_params
    kinds = set(filter(None, q.get("kinds", "").split(","))) or None
    return JSONResponse({"records": TRAIL.tail(int(q.get("limit", 300)), kinds), "total": len(TRAIL)})


async def audit_verify(request: Request) -> JSONResponse:
    return JSONResponse(await asyncio.to_thread(TRAIL.verify))


async def audit_stats(request: Request) -> JSONResponse:
    return JSONResponse(TRAIL.stats())


async def audit_export(request: Request) -> Response:
    body = "".join(json.dumps(r, default=str) + "\n" for r in TRAIL.tail(10**9))
    return Response(body, media_type="application/x-ndjson",
                    headers={"Content-Disposition": "attachment; filename=vajra-audit.jsonl"})


async def audit_stream(request: Request) -> Any:
    """Server-Sent Events: every new audit record, as it is written."""
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    unsubscribe = TRAIL.subscribe(lambda rec: loop.call_soon_threadsafe(queue.put_nowait, rec))

    async def events():
        try:
            while True:
                try:
                    rec = await asyncio.wait_for(queue.get(), timeout=15)
                    yield {"data": json.dumps(rec, default=str)}
                except TimeoutError:
                    yield {"event": "ping", "data": "{}"}
        finally:
            unsubscribe()

    return EventSourceResponse(events())


async def convert_status(request: Request) -> JSONResponse:
    from .convert import ENGINES, TAMPER_TESTS, ilovepdf_ready

    return JSONResponse({"ilovepdf": ilovepdf_ready(), "engines": list(ENGINES), "tamper_tests": TAMPER_TESTS})


async def convert_run(request: Request) -> JSONResponse:
    """Image(s) to PDF through the PDF tool, with VAJRA checking everything before delivery."""
    from .convert import ENGINES, MAX_IMAGES, MAX_UPLOAD, TAMPER_TESTS, convert

    form = await request.form(max_files=MAX_IMAGES + 1)
    engine, how = str(form.get("engine", "ilovepdf")), str(form.get("tamper", "none"))
    if engine not in ENGINES or how not in TAMPER_TESTS:
        return JSONResponse({"error": "bad engine or test"}, status_code=400)
    uploads = []
    for f in form.getlist("files"):
        if hasattr(f, "read"):
            data = await f.read(MAX_UPLOAD + 1)
            if len(data) > MAX_UPLOAD:
                return JSONResponse({"error": f"{f.filename} is larger than {MAX_UPLOAD // 2**20} MB"}, status_code=413)
            uploads.append((f.filename or "image", data))
    return JSONResponse(await convert(uploads, engine, how))


async def convert_file(request: Request) -> Response:
    from .convert import delivered_file

    found = delivered_file(request.path_params["token"])
    if found is None:
        return JSONResponse({"error": "file not found or expired"}, status_code=404)
    path, name = found
    TRAIL.record("file.download", file=name)
    return FileResponse(path, media_type="application/pdf", filename=name)


async def selftest(request: Request) -> JSONResponse:
    """Run one deterministic check per threat against the live policy, and audit the outcome."""
    from .selftest import run_selftest

    report = await run_selftest()
    passed = sum(c["ok"] for t in report["threats"] for c in t["checks"])
    total = sum(len(t["checks"]) for t in report["threats"])
    TRAIL.record("selftest", ok=report["ok"], passed=passed, total=total)
    return JSONResponse(report)


async def monitor_status(request: Request) -> JSONResponse:
    return JSONResponse(SCANNER.status())


async def monitor_scan(request: Request) -> JSONResponse:
    return JSONResponse(await SCANNER.scan(reason="manual"))


async def monitor_config(request: Request) -> JSONResponse:
    body = await request.json()
    if "enabled" in body:
        SCANNER.enabled = bool(body["enabled"])
    if "simulate_drift" in body:
        SCANNER.simulate_drift = bool(body["simulate_drift"])
    if body.get("reset_baseline"):
        SCANNER.reset_baseline()
    return JSONResponse(SCANNER.status())


@asynccontextmanager
async def lifespan(app: Starlette):
    task = asyncio.create_task(SCANNER.run_forever())
    try:
        yield
    finally:
        task.cancel()


def create_app() -> Starlette:
    load_dotenv(ROOT / ".env")
    routes: list[Any] = [
        Route("/api/status", status),
        Route("/api/scenarios", scenarios),
        Route("/api/results", results),
        Route("/api/sandbox", sandbox),
        Route("/api/site", site),
        Route("/api/isolation", isolation),
        Route("/api/audit", audit_list),
        Route("/api/audit/verify", audit_verify),
        Route("/api/audit/stats", audit_stats),
        Route("/api/audit/export", audit_export),
        Route("/api/audit/stream", audit_stream),
        Route("/api/selftest", selftest),
        Route("/api/convert/status", convert_status),
        Route("/api/convert", convert_run, methods=["POST"]),
        Route("/api/convert/file/{token}", convert_file),
        Route("/api/monitor/status", monitor_status),
        Route("/api/monitor/scan", monitor_scan, methods=["POST"]),
        Route("/api/monitor/config", monitor_config, methods=["POST"]),
        Route("/api/winsandbox", winsandbox_state),
        Route("/api/winsandbox/start", winsandbox_start, methods=["POST"]),
        Route("/api/winsandbox/stop", winsandbox_stop, methods=["POST"]),
        Route("/api/run", run),
    ]
    if FRONTEND_DIST.is_dir():
        routes.append(Mount("/", StaticFiles(directory=FRONTEND_DIST, html=True)))
    return Starlette(routes=routes, lifespan=lifespan)
