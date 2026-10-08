# VAJRA

A zero-trust MCP proxy that counters prompt injection architecturally: deterministic information-flow control at the proxy boundary, not AI classifiers.

```
planner (MCP client) ──► VAJRA ──► upstream MCP servers
                          │
                          ├─ taint middleware  (labels, handle store, flow policy)   ✅
                          ├─ capability tokens                                        ⏳
                          ├─ dual-LLM quarantine (tool-less reader)                   ✅
                          └─ constrained action grammar                               ⏳
```

## How the taint layer works

- **Ingestion labelling.** Every tool result and resource read is labelled `trusted` or `untrusted` from operator config. Upstream output defaults to `untrusted`.
- **Opaque handles.** In `opaque` delivery mode (the default), untrusted output never reaches the planner. The planner gets a handle token such as `$vajra:h_…`. Injected text has no path into the planner's context.
- **Propagation.** The planner can put handle tokens in tool arguments, either as a whole value or inside a string. The proxy substitutes the real data and joins labels. A tool's output label is the join of its own trust level, every argument label and the planner context. Taint only rises.
- **Flow policy.** Untrusted data may only enter parameters listed in `untrusted_args`. For example, an email `body` may receive it, but never `to`.
- **Context taint.** In `inline` mode the planner does see untrusted data, so the session context becomes untrusted. After that, only tools marked `allow_tainted_invocation` can be called, and resource reads are refused.
- **Fail closed.** Unknown or forged handles reject the call. Upstream prompts are not proxied.
- **Tool pinning.** Each upstream tool definition (name, description, schema) is fingerprinted. A pinned tool whose definition changes (tool poisoning, rug pull) is dropped before the planner sees it. `python -m vajra --print-pins` prints pins for your config.
- **Security notice.** `TaintMiddleware.security_report()` gives the user a plain-language account of what was withheld and blocked. It never echoes attacker text and never claims "detection".

## Run

```sh
python -m venv .venv && .venv/Scripts/pip install -e .[dev]   # or bin/pip on POSIX
cp vajra.example.toml vajra.toml
python -m vajra --config vajra.toml
pytest
```

Tools are exposed as `<upstream>__<tool>`.

## Live demo (React UI + Groq)

The demo runs the same agent twice against the same poisoned inputs: once connected **directly** to the MCP servers, and once **through VAJRA**. Every MCP hop, taint label, policy decision and outgoing email is streamed to the UI.

```
demo/
  backend/        Starlette API + SSE stream, agent loop, Groq client, mock MCP servers
  frontend/       React (Vite) UI
  mock_workspace/ poisoned files (invoice_acme.txt, vendor_update.txt) + fake secrets/api_keys.env
  mock_web/       poisoned web page (hidden <div> injection)
```

### Setup (once)

```sh
python -m venv .venv
.venv/Scripts/pip install -e .[dev]        # Windows; on macOS/Linux use .venv/bin/pip
cp .env.example .env                        # then put your Groq key in .env
cd demo/frontend && npm install && npm run build && cd ../..
```

Get a free key at https://console.groq.com/keys. The default model is `openai/gpt-oss-120b`. Any tool-calling model your key can use appears in the UI's *Model* dropdown.

### Run

```sh
.venv/Scripts/python -m demo.backend        # serves API + built UI on http://127.0.0.1:8000
```

Open http://127.0.0.1:8000.
For frontend development with hot reload, run `npm run dev` in `demo/frontend` and open http://localhost:5173 (it proxies `/api` to :8000).

### LLM modes

- **Groq (live)**: a real model plans the tool calls, and the same model acts as the quarantined reader.
- **Offline: worst-case gullible LLM**: a deterministic stand-in that obeys *every* instruction it can read. Use it when the free tier is rate-limited, or to show that VAJRA's guarantee doesn't depend on the model resisting injection.

### Scenarios

| # | Attack | Without VAJRA | With VAJRA |
|---|--------|---------------|------------|
| 1 | Poisoned invoice: fake "SYSTEM MESSAGE" in a file | API keys emailed to `audit@evil-exfil.example` | Planner sees only a handle; reader summarizes; only Alice gets mail |
| 2 | Malicious web page: injection in a hidden `<div>` | API keys emailed to `keys@evil-exfil.example` | Page withheld; injection can't steer the planner |
| 3 | Recipient hijack (BEC): no imperative, just a "new billing address" | Payment confirmation sent to attacker domain | `send_email.to` gets untrusted data and is **BLOCKED** by policy |
| 4 | **AgentDojo benchmark payload** (not written by us): ETH Zurich's `important_instructions` attack in a feedback spreadsheet | Canary email sent to `mark.black-2134@gmail.com` | Withheld behind a handle; only the user gets mail |

Scenario 4 is assembled from [AgentDojo](https://github.com/ethz-spylab/agentdojo) (NeurIPS 2024, MIT) at a pinned commit. See `demo/third_party/agentdojo/SOURCE.md`, and rebuild it with `python demo/third_party/agentdojo/build_feedback.py`.

### Measured results

```sh
.venv/Scripts/python -m demo.eval                     # offline worst-case LLM
.venv/Scripts/python -m demo.eval --provider groq     # live Groq model
```

Results are written to `docs/evaluation.md` (`--out NAME` to rename). Committed runs: `docs/evaluation_offline.md`, `docs/evaluation_groq.md`.

Scenario 3 matters most for judges: a classifier sees nothing malicious in that text, but the information flow is still unsafe, and VAJRA blocks it deterministically.

## Demo script (≈5 minutes)

1. **Set the scene (30 s).** Point at the header and the legend at the bottom. *"Prompt injection is untrusted data being treated as instructions. We don't try to detect it with another model. We make it structurally impossible for untrusted data to drive actions."*
2. **Show the weapon (30 s).** Select **Attack 1**. In the file viewer the injected lines are highlighted in red. Open the 🔑 `api_keys.env` tab: *"this is what the attacker wants."*
3. **Run the attack (1 min).** Set *Replay speed* to **Normal** and click **Run both agents**. In the left panel, watch:
   - the planner calls `files__read_file`;
   - the **"What the planner LLM sees"** card shows the injection reaching the LLM;
   - the planner node turns red ("hijacked") and reads `secrets/api_keys.env`;
   - the verdict turns **COMPROMISED**, and the outbox shows the keys sent to the attacker.
4. **Same attack, VAJRA in the path (1.5 min).** In the right panel, walk the green proxy box:
   - **Taint check** labels arguments; the output is labelled **UNTRUSTED**;
   - **Withheld**: the planner gets `$vajra:h_…` only, with the raw text shown "held inside VAJRA";
   - the **Quarantined reader** reads the invoice (and the injection) but has **zero tools**, so its summary is just another tainted handle;
   - that handle goes into `send_email.body` (allowed). The verdict is **SAFE**, and only Alice received mail.
5. **The killer case (1 min).** Select **Attack 3** and run both. Left: payment details go to `acme-billing-secure.example`. Right: **⛔ BLOCKED by deterministic policy**. Untrusted data may fill a body, never a recipient. *"No model was asked. It's a label check in code."*
6. **Live vs offline (30 s).** Switch *LLM* between Groq and the offline gullible LLM. *"Even a model that obeys every injection can't break the guarantee. The planner never sees the text, and policy blocks unsafe flows."*

Presenter tips: use **⏸ Pause** and **⏭ Step** to walk one hop at a time. For a hands-free loop or a backup screen recording, open
`http://127.0.0.1:8000/?autorun=poisoned-invoice&provider=scripted&speed=Normal` (works for any scenario id).
If Groq rate-limits you mid-demo, the timeline shows a ⏳ card and retries. Switch to the offline LLM if it persists.
