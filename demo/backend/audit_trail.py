"""The demo's shared, persistent audit trail (one hash-chained JSONL file)."""

from pathlib import Path

from vajra.audit import AuditLog

TRAIL = AuditLog(Path(__file__).resolve().parents[2] / ".vajra-audit" / "audit.jsonl")
