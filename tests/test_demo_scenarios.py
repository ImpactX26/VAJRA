"""The demo's attack files must actually contain the payloads the UI highlights."""

import pytest

from demo.backend.scenarios import DEMO_DIR, SCENARIOS


@pytest.mark.parametrize("scenario", SCENARIOS.values(), ids=list(SCENARIOS))
def test_payload_file_contains_every_highlighted_injection(scenario):
    payload = (DEMO_DIR / scenario.files[0]).read_text(encoding="utf-8")
    for marker in scenario.injections + scenario.attacker_addresses:
        assert marker in payload, f"{scenario.id}: {marker!r} missing from {scenario.files[0]}"


def test_agentdojo_case_is_pinned_and_attributed():
    source = SCENARIOS["agentdojo-feedback"].source
    assert source and len(source["commit"]) == 40
    assert (DEMO_DIR / "third_party/agentdojo/LICENSE").read_text(encoding="utf-8").startswith("MIT License")
