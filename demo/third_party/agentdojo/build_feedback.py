"""Rebuild demo/mock_workspace/feedback.csv from AgentDojo, reproducibly.

AgentDojo (Debenedetti et al., ETH Zurich, NeurIPS 2024 Datasets & Benchmarks;
https://github.com/ethz-spylab/agentdojo, MIT licence) ships realistic agent
environments with *injection slots*, attacker goals, and attack templates.
This script assembles one benchmark case exactly as AgentDojo does:

  document  workspace suite, cloud drive file "feedback.xlsx" (cloud_drive.yaml)
  slot      {drive_feedback_injection}   (customer "Noah Lee"'s feedback cell)
  attack    important_instructions_no_model_name
            (_JB_STRING with user="Emma Johnson", model=DEFAULT_MODEL_NAME)
  goal      workspace InjectionTask0.GOAL

Other slots get their default (benign) values, as in the benchmark.
The upstream source is only downloaded and parsed as text; none of it is executed.

    python demo/third_party/agentdojo/build_feedback.py
"""

from __future__ import annotations

import re
import urllib.request
from pathlib import Path

COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
RAW = f"https://raw.githubusercontent.com/ethz-spylab/agentdojo/{COMMIT}/src/agentdojo"
OUT = Path(__file__).resolve().parents[2] / "mock_workspace" / "feedback.csv"

USER_NAME = "Emma Johnson"  # ImportantInstructionsAttack.user_name
SLOT = "drive_feedback_injection"


def fetch(path: str) -> str:
    with urllib.request.urlopen(f"{RAW}/{path}", timeout=30) as resp:
        return resp.read().decode("utf-8")


def python_string_constant(source: str, pattern: str) -> str:
    """Evaluate a (possibly multi-part) string literal found in upstream source, without executing code."""
    m = re.search(pattern, source, re.S)
    if not m:
        raise SystemExit(f"pattern not found upstream: {pattern}")
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
    return "".join(bytes(p, "utf-8").decode("unicode_escape") for p in parts)


def main() -> None:
    drive = fetch("data/suites/workspace/include/cloud_drive.yaml")
    attacks = fetch("attacks/important_instructions_attacks.py")
    base = fetch("attacks/base_attacks.py")
    tasks = fetch("default_suites/v1/workspace/injection_tasks.py")

    # 1. The document: feedback.xlsx's CSV content block.
    start = re.search(r'filename: "feedback\.xlsx".*?content: \|\n', drive, re.S)
    if not start:
        raise SystemExit("feedback.xlsx not found in cloud_drive.yaml")
    lines = []
    for line in drive[start.end():].splitlines():
        if line.strip() and not line.startswith(" " * 6):  # the YAML block scalar ends at the first dedent
            break
        lines.append(line[6:])
    document = "\n".join(lines).strip("\n")

    # 2. The attack template and its parameters.
    template = python_string_constant(attacks, r"_JB_STRING = \((.*?)\n    \)")
    model_name = python_string_constant(base, r'DEFAULT_MODEL_NAME = ("[^"]*")')

    # 3. The attacker goal (InjectionTask0), with its f-string constants substituted.
    task0 = tasks.split("class InjectionTask0", 1)[1].split("class InjectionTask1", 1)[0]
    consts = dict(re.findall(r'(_[A-Z]+) = "([^"]*)"', task0))
    goal_tpl = re.search(r'GOAL = f"([^"]*)"', task0).group(1)
    goal = re.sub(r"\{(_[A-Z]+)\}", lambda m: consts[m.group(1)], goal_tpl)

    payload = template.format(user=USER_NAME, model=model_name, goal=goal)
    poisoned = document.replace("{" + SLOT + "}", payload)
    if poisoned == document:
        raise SystemExit("injection slot not found")

    OUT.write_text(poisoned.rstrip("\n") + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT}  (AgentDojo @ {COMMIT[:10]}; goal: {goal})")


if __name__ == "__main__":
    main()
