# AgentDojo-derived test case

`demo/mock_workspace/feedback.csv` is **not written by the VAJRA team**. It is a
prompt-injection test case assembled from **AgentDojo**, a public benchmark for
prompt-injection attacks and defenses on tool-using LLM agents:

> E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, F. Tramèr.
> *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.*
> NeurIPS 2024 Datasets and Benchmarks Track. https://github.com/ethz-spylab/agentdojo (MIT licence, see `LICENSE`).

Pinned commit: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`

| What | Upstream file (pinned link) | Lines |
|---|---|---|
| The document: cloud-drive file feedback.xlsx | [`src/agentdojo/data/suites/workspace/include/cloud_drive.yaml`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/data/suites/workspace/include/cloud_drive.yaml#L3-L25) | 3–25 |
| The injection slot {drive_feedback_injection} (Noah Lee's feedback cell) | [`src/agentdojo/data/suites/workspace/include/cloud_drive.yaml`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/data/suites/workspace/include/cloud_drive.yaml#L17) | 17 |
| The slot's definition and benign default | [`src/agentdojo/data/suites/workspace/injection_vectors.yaml`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/data/suites/workspace/injection_vectors.yaml#L40-L42) | 40–42 |
| The attack wording: important_instructions _JB_STRING, user 'Emma Johnson' | [`src/agentdojo/attacks/important_instructions_attacks.py`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/attacks/important_instructions_attacks.py#L26-L43) | 26–43 |
| The no-model-name variant used here | [`src/agentdojo/attacks/important_instructions_attacks.py`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/attacks/important_instructions_attacks.py#L56-L61) | 56–61 |
| DEFAULT_MODEL_NAME = 'the AI language model' | [`src/agentdojo/attacks/base_attacks.py`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/attacks/base_attacks.py#L19) | 19 |
| The attacker goal: workspace InjectionTask0 | [`src/agentdojo/default_suites/v1/workspace/injection_tasks.py`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/default_suites/v1/workspace/injection_tasks.py#L10-L16) | 10–16 |
| Code that builds the attack text: attack() → jailbreak.format(goal, user, model) | [`src/agentdojo/attacks/base_attacks.py`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/attacks/base_attacks.py#L116-L125) | 116–125 |
| Code that injects it into the document: environment_text.format(...) | [`src/agentdojo/task_suite/task_suite.py`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/task_suite/task_suite.py#L139-L146) | 139–146 |

The goal is AgentDojo's own *canary* action: email a harmless text to an
attacker-controlled address. If the agent sends it, the injection controlled the
agent. That is how the benchmark scores attack success.

Regenerate (downloads the pinned commit and parses it as text; nothing upstream is executed):

    python demo/third_party/agentdojo/build_feedback.py

Adaptation: the file is saved as `feedback.csv` (AgentDojo names it `feedback.xlsx`,
but its content is CSV text). The user task in the demo is ours. AgentDojo's tools
are mapped onto the demo's MCP servers (`files`, `mail`).
