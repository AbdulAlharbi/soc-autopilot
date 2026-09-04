"""Claude-backed brain.

Uses the Anthropic Messages API. Each decision is a single request that must
return a JSON object matching the supplied pydantic schema; malformed output
is fed back once for repair, then falls through to the heuristic brain so the
workflow never stalls on a model hiccup.
"""
from __future__ import annotations

import json
import re
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .heuristic import HeuristicBrain

T = TypeVar("T", bound=BaseModel)

SYSTEM_BASE = """You are a senior SOC analyst embedded in an autonomous incident-response system.
You reason carefully over evidence, are explicit about uncertainty, and never invent facts that are not in the context.
You prefer the least disruptive action that fully contains the threat, and you flag when a decision has business impact a human should own.
When asked for JSON, respond with ONLY a JSON object — no prose, no markdown fences."""

MAX_CONTEXT_CHARS = 40_000


def _compact(context: dict[str, Any]) -> str:
    text = json.dumps(context, default=str, indent=1)
    if len(text) > MAX_CONTEXT_CHARS:
        text = text[:MAX_CONTEXT_CHARS] + "\n...<context truncated>"
    return text


def _extract_json(text: str) -> str:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fence:
        return fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    return text[start : end + 1] if start != -1 and end != -1 else text


class ClaudeBrain:
    name = "claude"

    def __init__(self, model: str = "claude-sonnet-4-5", max_tokens: int = 2500, temperature: float = 0.1):
        import anthropic  # imported lazily so the heuristic path has no SDK dependency

        self.client = anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.fallback = HeuristicBrain()
        self.calls = 0

    # ------------------------------------------------------------------ #
    def _complete(self, system: str, messages: list[dict[str, Any]]) -> str:
        self.calls += 1
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system,
            messages=messages,
        )
        return "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")

    def decide(self, task: str, context: dict[str, Any], schema: type[T], system: str = "") -> T:
        schema_json = json.dumps(schema.model_json_schema(), indent=1)
        prompt = (
            f"TASK: {task}\n\n"
            f"CONTEXT:\n{_compact(context)}\n\n"
            f"Return ONLY a JSON object that validates against this schema:\n{schema_json}"
        )
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        sys_prompt = SYSTEM_BASE + ("\n\n" + system if system else "")
        last_error = ""
        for _ in range(2):
            try:
                raw = self._complete(sys_prompt, messages)
                return schema.model_validate_json(_extract_json(raw))
            except (ValidationError, json.JSONDecodeError, ValueError) as exc:
                last_error = str(exc)
                messages += [
                    {"role": "assistant", "content": raw if "raw" in locals() else ""},
                    {"role": "user", "content": f"That did not validate: {exc}. Return corrected JSON only."},
                ]
            except Exception as exc:  # network / auth / rate limit
                last_error = str(exc)
                break
        result = self.fallback.decide(task, context, schema, system)
        if hasattr(result, "rationale"):
            result.rationale = f"[heuristic fallback after model error: {last_error[:120]}] " + result.rationale
        return result

    def narrate(self, task: str, context: dict[str, Any], system: str = "") -> str:
        prompt = f"TASK: {task}\n\nCONTEXT:\n{_compact(context)}\n\nWrite the requested text in plain prose or markdown."
        try:
            return self._complete(SYSTEM_BASE + ("\n\n" + system if system else ""),
                                  [{"role": "user", "content": prompt}]).strip()
        except Exception:
            return self.fallback.narrate(task, context, system)
