"""The demo's shared, persistent audit trail (one hash-chained JSONL file).

VAJRA_AUDIT_FILE overrides the location (the test suite uses this to keep its records out of the demo trail).
"""

import os
from pathlib import Path

from vajra.audit import AuditLog

DEFAULT = Path(__file__).resolve().parents[2] / ".vajra-audit" / "audit.jsonl"
TRAIL = AuditLog(Path(os.environ.get("VAJRA_AUDIT_FILE") or DEFAULT))
