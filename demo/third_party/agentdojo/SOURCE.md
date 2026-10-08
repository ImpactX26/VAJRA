# AgentDojo-derived test case

`demo/mock_workspace/feedback.csv` is **not written by the VAJRA team**. It is a
prompt-injection test case assembled from **AgentDojo**, a public benchmark for
prompt-injection attacks and defenses on tool-using LLM agents:

> E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, F. Tramèr.
> *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.*
> NeurIPS 2024 Datasets and Benchmarks Track. https://github.com/ethz-spylab/agentdojo (MIT licence, see `LICENSE`).

Pinned commit: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`

| Piece | Upstream file |
|---|---|
| Document: cloud-drive file `feedback.xlsx` (CSV content) | `src/agentdojo/data/suites/workspace/include/cloud_drive.yaml` |
| Injection slot: `{drive_feedback_injection}` (customer Noah Lee's feedback cell) | same file, line 17; described in `data/suites/workspace/injection_vectors.yaml` |
| Attack template: `important_instructions_no_model_name` | `src/agentdojo/attacks/important_instructions_attacks.py` (`_JB_STRING`), `attacks/base_attacks.py` (`DEFAULT_MODEL_NAME`) |
| Attacker goal: workspace `InjectionTask0` | `src/agentdojo/default_suites/v1/workspace/injection_tasks.py` |

The goal is AgentDojo's own *canary* action: email a harmless text to an
attacker-controlled address. If the agent sends it, the injection controlled the
agent. That is how the benchmark scores attack success.

Regenerate (downloads the pinned commit and parses it as text; nothing upstream is executed):

    python demo/third_party/agentdojo/build_feedback.py

Adaptation: the file is saved as `feedback.csv` (AgentDojo names it `feedback.xlsx`,
but its content is CSV text). The user task in the demo is ours. AgentDojo's tools
are mapped onto the demo's MCP servers (`files`, `mail`).
