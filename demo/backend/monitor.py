"""Continuous monitoring: alert rules over the audit trail, plus a background
integrity scanner that re-fingerprints every MCP server's tools on a schedule
and raises a critical alert when any definition drifts from the baseline.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from collections import deque
from pathlib import Path
from typing import Any

from vajra.audit import AuditLog
from vajra.config import ToolConfig, UpstreamConfig
from vajra.proxy import UpstreamManager

from . import winsandbox
from .audit_trail import TRAIL
from .runner import MOCK_SERVERS, upstream_configs

REVIEWED_PIN = "sha256:6f1d0c2a9b7e4f3a8c5d2e1b0a9f8e7d"

REPEAT_WINDOW_S = 600
REPEAT_THRESHOLD = 3


class AlertEngine:
    """Deterministic rules evaluated on every audit record; alerts are themselves audited."""

    def __init__(self, trail: AuditLog) -> None:
        self.trail = trail
        self._blocks: deque[float] = deque()
        self._repeat_alerted_at = 0.0
        trail.subscribe(self.on_record)

    def _alert(self, severity: str, title: str, **fields: Any) -> None:
        self.trail.record("alert", severity=severity, title=title, **fields)

    def on_record(self, rec: dict[str, Any]) -> None:
        kind = rec.get("kind")
        if kind == "tool.reject":
            if "pin mismatch" in (rec.get("reason") or ""):
                self._alert("critical", f"Tool definition changed since review: {rec.get('tool')}", source_seq=rec["seq"])
            else:
                self._alert("high", f"Unsafe tool rejected: {rec.get('tool')}", detail=rec.get("reason"), source_seq=rec["seq"])
        elif kind == "block":
            self._alert("high", f"Unsafe action blocked: {rec.get('tool')}", detail=(rec.get("reason") or "")[:160], source_seq=rec["seq"])
            now = time.time()
            self._blocks.append(now)
            while self._blocks and now - self._blocks[0] > REPEAT_WINDOW_S:
                self._blocks.popleft()
            if len(self._blocks) >= REPEAT_THRESHOLD and now - self._repeat_alerted_at > REPEAT_WINDOW_S:
                self._repeat_alerted_at = now
                self._alert("critical", f"Repeated blocked actions: {len(self._blocks)} in 10 minutes", source_seq=rec["seq"])
        elif kind == "sanitize":
            n = len(rec.get("removed") or [])
            self._alert("medium", f"Hidden content removed from {rec.get('tool')}: {n} part(s)", source_seq=rec["seq"])
        elif kind == "taint_context":
            self._alert("high", "Planner context became untrusted (inline delivery)", source_seq=rec["seq"])
        elif kind == "monitor.drift":
            self._alert("critical", f"Tool drift detected: {rec.get('tool')} ({rec.get('change')})", source_seq=rec["seq"])


class IntegrityScanner:
    """Periodically connects to every MCP server through the sandbox and compares tool fingerprints."""

    def __init__(self, trail: AuditLog, interval_s: int = 120) -> None:
        self.trail = trail
        self.interval_s = interval_s
        self.enabled = True
        self.simulate_drift = False
        self.baseline: dict[str, str] | None = None
        self.last: dict[str, Any] | None = None
        self.next_at: float | None = None
        self._lock = asyncio.Lock()
        self._vm_ready: bool | None = None
        self._reported: dict[str, str | None] = {}
        """Drift already alerted, per tool (fingerprint at the time), so a persisting change alerts once."""

    def _configs(self, outbox: Path) -> dict[str, UpstreamConfig]:
        configs = upstream_configs(outbox)
        env = {"VAJRA_TOOL_DRIFT": "1"} if self.simulate_drift else None
        configs["toolbox"] = UpstreamConfig(
            "toolbox", sys.executable, args=(MOCK_SERVERS, "--role", "toolbox"), env=env,
            tools={"lookup_record": ToolConfig(pin=REVIEWED_PIN)},
        )
        return configs

    async def scan(self, reason: str = "scheduled") -> dict[str, Any]:
        async with self._lock:
            started = time.time()
            with tempfile.TemporaryDirectory(prefix="vajra-monitor-") as tmp:
                async with UpstreamManager(self._configs(Path(tmp) / "outbox.jsonl"), sandbox=True, isolation="job") as ups:
                    current = {f"{a.server}/{a.tool}": a.fingerprint for a in ups.admissions}
                    rejected = sum(not a.admitted for a in ups.admissions)
                    isolation = {n: u.isolation for n, u in ups.upstreams.items()}
            drift = []
            if self.baseline is not None:
                for tool, fp in current.items():
                    if tool not in self.baseline:
                        drift.append((tool, "new tool appeared"))
                    elif self.baseline[tool] != fp:
                        drift.append((tool, "definition changed"))
                drift += [(tool, "tool disappeared") for tool in self.baseline if tool not in current]
            else:
                self.baseline = current
            for tool, change in drift:
                if self._reported.get(tool, "-") != current.get(tool):  # new or different drift only
                    self._reported[tool] = current.get(tool)
                    self.trail.record("monitor.drift", tool=tool, change=change, fingerprint=current.get(tool))
            for tool in [t for t in self._reported if t not in {d[0] for d in drift}]:
                del self._reported[tool]  # back to baseline: a future change alerts again
            self.last = {
                "at": time.time(), "reason": reason, "tools": len(current), "rejected": rejected,
                "drift": [{"tool": t, "change": c} for t, c in drift], "duration_s": round(time.time() - started, 1),
                "isolation": sorted(set(isolation.values())),
            }
            self.trail.record("monitor.scan", reason=reason, tools=len(current), rejected=rejected, drift=len(drift),
                              duration_s=self.last["duration_s"])
            await self._check_vm()
            return self.last

    async def _check_vm(self) -> None:
        vm = await asyncio.to_thread(winsandbox.state)
        if vm["ready"] != self._vm_ready:
            self._vm_ready = vm["ready"]
            self.trail.record("monitor.vm", ready=vm["ready"], url=vm.get("url"))

    def reset_baseline(self) -> None:
        self.baseline = None
        self._reported.clear()

    async def run_forever(self) -> None:
        await asyncio.sleep(3)
        while True:
            if self.enabled:
                try:
                    await self.scan()
                except Exception as e:  # the monitor must keep running
                    self.trail.record("monitor.error", error=f"{type(e).__name__}: {e}"[:300])
            self.next_at = time.time() + self.interval_s
            await asyncio.sleep(self.interval_s)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled, "interval_s": self.interval_s, "simulate_drift": self.simulate_drift,
            "baseline_tools": len(self.baseline or {}), "last": self.last, "next_at": self.next_at,
        }


ALERTS = AlertEngine(TRAIL)
SCANNER = IntegrityScanner(TRAIL)
