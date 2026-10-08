"""Tamper-evident audit trail.

Every security decision VAJRA makes is appended to a JSON-lines file as a record
that carries the SHA-256 hash of the previous record (a hash chain). Editing,
reordering or deleting any past record breaks the chain, and ``verify()`` reports
exactly where.

Records hold metadata only: tool names, argument labels, reasons, sizes and
fingerprints. Untrusted content (which may contain attacker text) and secrets are
never written; removed content is represented by its SHA-256 fingerprint.

Several processes may write the same file (the web server, scripts, tests). Each write
takes an exclusive lock on a sidecar ``.lock`` file and first reads any records other
processes appended, so the chain always continues from the true last record on disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from contextlib import contextmanager
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def fingerprint(text: str) -> str:
    """Stable reference to content without storing it."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:24]


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@contextmanager
def _exclusive(lock_path: Path):
    """Cross-process exclusive lock held on a sidecar file (Windows and POSIX)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as f:
        if os.name == "nt":
            import msvcrt

            f.seek(0)
            while True:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.01)
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


class AuditLog:
    def __init__(self, path: Path | str | None = None) -> None:
        """``path=None`` keeps the trail in memory only (tests)."""
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self._offset = 0
        """Bytes of the file already loaded into ``_records``."""
        if self.path and self.path.exists():
            self._load_new()

    def _load_new(self) -> list[dict[str, Any]]:
        """Read records appended to the file since the last read (by this or another process)."""
        assert self.path is not None
        with self.path.open("rb") as f:
            f.seek(self._offset)
            data = f.read()
        complete = data[: data.rfind(b"\n") + 1]  # never consume a half-written line
        self._offset += len(complete)
        new = []
        for line in complete.decode("utf-8").splitlines():
            if line.strip():
                try:
                    new.append(json.loads(line))
                except ValueError:
                    new.append({"seq": len(self._records) + len(new), "kind": "corrupt", "raw": line[:200]})
        self._records.extend(new)
        return new

    # ------------------------------------------------------------------ writing
    def record(self, kind: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            if self.path:
                with _exclusive(self.path.with_name(self.path.name + ".lock")):
                    if self.path.exists():
                        self._load_new()
                    rec = self._next(kind, fields)
                    line = (json.dumps(rec, default=str) + "\n").encode("utf-8")
                    with self.path.open("ab") as f:
                        f.write(line)
                        f.flush()
                        os.fsync(f.fileno())
                    self._offset += len(line)
            else:
                rec = self._next(kind, fields)
            self._records.append(rec)
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(rec)
            except Exception:  # a broken listener must never block auditing
                pass
        return rec

    def _next(self, kind: str, fields: dict[str, Any]) -> dict[str, Any]:
        prev = self._records[-1]["hash"] if self._records and "hash" in self._records[-1] else GENESIS
        rec = {
            "seq": len(self._records),
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "kind": kind,
            **fields,
            "prev": prev,
        }
        rec["hash"] = _digest(rec)
        return rec

    def subscribe(self, listener: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        with self._lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return unsubscribe

    # ------------------------------------------------------------------ reading
    def _refresh(self) -> None:
        if self.path and self.path.exists():
            self._load_new()

    def tail(self, limit: int = 200, kinds: set[str] | None = None) -> list[dict[str, Any]]:
        with self._lock:
            self._refresh()
            recs = [r for r in self._records if not kinds or r.get("kind") in kinds]
        return recs[-limit:]

    def __len__(self) -> int:
        return len(self._records)

    def verify(self) -> dict[str, Any]:
        """Recompute the chain. Reports the first record that does not match."""
        with self._lock:
            self._refresh()
            records = list(self._records)
        prev = GENESIS
        for i, rec in enumerate(records):
            if rec.get("seq") != i:
                return {"ok": False, "records": len(records), "broken_at": i, "reason": "sequence gap or reorder"}
            if rec.get("prev") != prev:
                return {"ok": False, "records": len(records), "broken_at": i, "reason": "previous-hash mismatch"}
            if rec.get("hash") != _digest(rec):
                return {"ok": False, "records": len(records), "broken_at": i, "reason": "record was modified"}
            prev = rec["hash"]
        return {"ok": True, "records": len(records), "broken_at": None, "head": prev}

    def stats(self) -> dict[str, Any]:
        with self._lock:
            self._refresh()
            records = list(self._records)
        kinds = Counter(r.get("kind") for r in records)
        servers = Counter(r.get("tool", "").split("/")[0] for r in records if r.get("kind") in ("call", "block", "withhold", "sanitize"))
        severities = Counter(r.get("severity") for r in records if r.get("kind") == "alert")
        return {
            "records": len(records),
            "kinds": dict(kinds),
            "by_server": dict(servers),
            "alerts": dict(severities),
            "first": records[0]["ts"] if records else None,
            "last": records[-1]["ts"] if records else None,
        }
