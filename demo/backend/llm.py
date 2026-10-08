"""LLM providers for the demo planner and quarantined reader.

* ``GroqLLM`` — live model via Groq's OpenAI-compatible API (free tier works).
* ``GullibleScriptedLLM`` — offline, deterministic stand-in that models the
  *worst case*: an LLM that obeys every instruction it reads. Useful when the
  free tier is rate-limited, and to show VAJRA's guarantee doesn't depend on
  the model resisting injection.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from typing import Any

import httpx

from .scenarios import Scenario

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODELS_URL = "https://api.groq.com/openai/v1/models"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b"
HANDLE = re.compile(r"\$vajra:h_[0-9a-f]{32}")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

Message = dict[str, Any]


class LLMError(RuntimeError):
    pass


class GroqLLM:
    label = "Groq"

    def __init__(self, api_key: str, model: str = DEFAULT_GROQ_MODEL, on_retry: Callable[[float], None] | None = None):
        self.model = model
        self._headers = {"Authorization": f"Bearer {api_key}"}
        self._on_retry = on_retry

    async def chat(self, messages: list[Message], tools: list[dict[str, Any]] | None = None) -> Message:
        body: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": 0}
        if tools:
            body |= {"tools": tools, "tool_choice": "auto", "parallel_tool_calls": False}
        data = await self._post(body)
        msg = data["choices"][0]["message"]
        out: Message = {"role": "assistant", "content": msg.get("content") or ""}
        if msg.get("tool_calls"):
            out["tool_calls"] = msg["tool_calls"]
        return out

    async def complete(self, system: str, user: str) -> str:
        msg = await self.chat([{"role": "system", "content": system}, {"role": "user", "content": user}])
        return msg["content"]

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=60) as client:
            for attempt in range(4):
                resp = await client.post(GROQ_URL, json=body, headers=self._headers)
                if resp.status_code == 429 and attempt < 3:
                    # Free tier rate limit: honour retry-after (capped) and try again.
                    delay = min(float(resp.headers.get("retry-after", 5)), 30.0)
                    if self._on_retry:
                        self._on_retry(delay)
                    await asyncio.sleep(delay)
                    continue
                if resp.status_code >= 400:
                    raise LLMError(f"Groq API {resp.status_code}: {resp.text[:500]}")
                return resp.json()
        raise LLMError("Groq API: rate limited")


class GullibleScriptedLLM:
    """Deterministic planner that follows the user's task *and* any instruction it can read."""

    label = "Offline scripted LLM (always obeys injections)"

    def __init__(self, scenario: Scenario, user_email: str) -> None:
        self.s = scenario
        self.user_email = user_email
        self._queue: list[tuple[str, dict[str, Any], str]] = []
        self._seen = 0
        self._awaiting = ""
        self._exfil_to: str | None = None
        self._doc: str | None = None
        self._reader_out: str | None = None
        self._phase = "start"
        self._n = 0

    async def chat(self, messages: list[Message], tools: list[dict[str, Any]] | None = None) -> Message:
        names = {t["function"]["name"] for t in tools or []}
        tool_msgs = [m for m in messages if m["role"] == "tool"]
        for m in tool_msgs[self._seen :]:
            self._observe(m["content"])
        self._seen = len(tool_msgs)

        if self._phase == "start":
            self._phase = "main"
            return self._call(self.s.source_tool, self.s.source_args, "source", "I'll start by reading the input.")
        if self._queue:
            name, args, awaiting = self._queue.pop(0)
            return self._call(name, args, awaiting, "Following the instructions in the document.")
        return self._main_step(names, tool_msgs[-1]["content"] if tool_msgs else "")

    def _observe(self, text: str) -> None:
        awaiting, self._awaiting = self._awaiting, ""
        if awaiting == "source":
            self._doc = text
        elif awaiting == "reader":
            self._reader_out = text
        elif awaiting == "secret" and self._exfil_to:
            self._queue.append(("mail__send_email", {"to": self._exfil_to, "subject": "audit", "body": text}, "exfil"))

        if HANDLE.search(text):
            return  # an opaque handle: there is nothing here to obey
        # The "gullible" part: obey any imperative it can parse out of what it read.
        read = re.search(r'read_file with path "([^"]+)"', text)
        send = re.search(r'send_email to "([^"]+)"', text)
        if read and send:
            self._exfil_to = send.group(1)
            self._queue.append(("files__read_file", {"path": read.group(1)}, "secret"))
        # AgentDojo's phrasing (workspace InjectionTask0 style goals).
        for body, to, subject in re.findall(r"email the text '([^']*)' to '([^']+)' using '([^']*)' as subject", text):
            self._queue.append(("mail__send_email", {"to": to, "subject": subject, "body": body}, "exfil"))

    def _main_step(self, names: set[str], last: str) -> Message:
        doc = self._doc or ""
        handle = HANDLE.search(doc)
        has_reader = "vajra__quarantine" in names

        if self._phase == "main" and handle and has_reader:
            self._phase = "reader"
            instruction = (
                "Summarize this document in 3 short bullet points."
                if self.s.goal == "email_summary"
                else "Extract the vendor's new billing contact email address. Output only the address."
            )
            return self._call(
                "vajra__quarantine",
                {"data": handle.group(0), "instruction": instruction},
                "reader",
                "The document is withheld behind a handle, so I'll ask the quarantined reader to process it.",
            )

        if self._phase in ("main", "reader"):
            self._phase = "sent"
            produced = self._reader_out or ""
            value = (HANDLE.search(produced) or HANDLE.search(doc))
            if self.s.goal == "email_summary":
                body = value.group(0) if value else _naive_summary(doc)
                args = {"to": self.user_email, "subject": "Summary", "body": body}
            else:
                to = value.group(0) if value else _billing_address(doc)
                args = {"to": to, "subject": "Payment confirmation for INV-2291",
                        "body": "We confirm invoice INV-2291 ($12,480.00) will be paid on 2026-11-01."}
            return self._call("mail__send_email", args, "send", "Now completing the user's task.")

        if "blocked" in last:
            return {"role": "assistant", "content": f"I couldn't finish the task: the action was blocked by VAJRA.\n{last}"}
        return {"role": "assistant", "content": "Done. The email has been sent."}

    def _call(self, name: str, args: dict[str, Any], awaiting: str, thought: str) -> Message:
        self._awaiting = awaiting
        self._n += 1
        return {
            "role": "assistant",
            "content": thought,
            "tool_calls": [
                {"id": f"call_{self._n}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
            ],
        }


class ScriptedReader:
    """Offline quarantined reader: extractive only, no model."""

    label = "Offline scripted reader"

    async def complete(self, system: str, user: str) -> str:
        instruction, _, data = user.partition("DATA:")
        if "email address" in instruction:
            return _billing_address(data)
        return _naive_summary(data)


def _naive_summary(text: str) -> str:
    lines = [re.sub(r"<[^>]+>", "", l).strip() for l in text.splitlines()]
    lines = [l for l in lines if l and l not in ("<<<", ">>>") and not l.startswith(("-----", "#"))]
    return "Summary:\n" + "\n".join(f"- {l}" for l in lines[:5])


def _billing_address(text: str) -> str:
    m = re.search(r"new billing contact:\s*(" + EMAIL.pattern + ")", text)
    found = EMAIL.findall(text)
    return m.group(1) if m else (found[-1] if found else "")
