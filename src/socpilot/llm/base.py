"""Brain interface.

Agents never talk to an LLM directly. They hand a *task name*, a *context*
dict, and a pydantic *schema* to a Brain and get back a validated object. That
gives three properties we want in an enterprise workflow:

  * the same agent code runs with Claude or with a deterministic rule set
    (`HeuristicBrain`) — useful for CI, demos without API keys, and as a
    fallback if the model endpoint is unavailable;
  * model output is always validated before it can influence state;
  * every decision records which brain produced it.
"""
from __future__ import annotations

from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class Brain(Protocol):
    name: str

    def decide(self, task: str, context: dict[str, Any], schema: type[T], system: str = "") -> T: ...

    def narrate(self, task: str, context: dict[str, Any], system: str = "") -> str: ...


def make_brain(kind: str, model: str | None = None) -> Brain:
    if kind == "claude":
        from .claude import ClaudeBrain

        return ClaudeBrain(model=model or "claude-sonnet-4-5")
    if kind == "heuristic":
        from .heuristic import HeuristicBrain

        return HeuristicBrain()
    raise ValueError(f"unknown brain kind {kind!r} (expected 'claude' or 'heuristic')")
