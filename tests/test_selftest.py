"""The live self-test shown on the Threats page must pass for every threat."""

from demo.backend.selftest import run_selftest


async def test_every_threat_check_passes():
    report = await run_selftest()
    failed = [(t["id"], c["name"], c["detail"]) for t in report["threats"] for c in t["checks"] if not c["ok"]]
    assert report["ok"] and not failed, failed
    assert {t["id"] for t in report["threats"]} == {"indirect", "poisoning", "lateral", "exfiltration", "downstream"}
