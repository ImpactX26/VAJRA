"""Test-wide setup: tests never write into the demo's real audit trail."""

import os
import tempfile
from pathlib import Path

os.environ.setdefault("VAJRA_AUDIT_FILE", str(Path(tempfile.mkdtemp(prefix="vajra-test-audit-")) / "audit.jsonl"))
