"""ClaudeBrain contract tests with a stubbed API client (no network, no key)."""
import types

import pytest

anthropic = pytest.importorskip("anthropic")

from socpilot.llm.claude import ClaudeBrain  # noqa: E402
from socpilot.models import TriageDecision  # noqa: E402


class _Resp:
    def __init__(self, text):
        self.content = [types.SimpleNamespace(type="text", text=text)]


class _Client:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), 0
        self.messages = self

    def create(self, **kw):
        self.calls += 1
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return _Resp(r)


def _brain(replies):
    b = ClaudeBrain.__new__(ClaudeBrain)
    b.client, b.model, b.max_tokens, b.temperature, b.calls = _Client(replies), "test", 100, 0, 0
    from socpilot.llm.heuristic import HeuristicBrain
    b.fallback = HeuristicBrain()
    return b


GOOD = '{"verdict":"true_positive","severity":"high","confidence":0.9,"category":"malware_c2","rationale":"x","mitre_techniques":["T1071"]}'


def test_parses_plain_json():
    d = _brain([GOOD]).decide("triage", {}, TriageDecision)
    assert d.category == "malware_c2" and d.confidence == 0.9


def test_strips_markdown_fences_and_prose():
    d = _brain(["Sure, here you go:\n```json\n" + GOOD + "\n```"]).decide("triage", {}, TriageDecision)
    assert d.verdict.value == "true_positive"


def test_repairs_invalid_output_once():
    b = _brain(['{"verdict":"nope"}', GOOD])
    d = b.decide("triage", {}, TriageDecision)
    assert d.severity.value == "high" and b.client.calls == 2


def test_falls_back_to_heuristic_on_api_error():
    ctx = {"alert": {"tags": ["beaconing"], "src_ip": "10.0.0.1"}, "signals": {"beaconing": True, "ti_malicious": [{"ioc": "1.1.1.1"}], "suspicious_process_count": 1}}
    d = _brain([RuntimeError("rate limited")]).decide("triage", ctx, TriageDecision)
    assert d.category == "malware_c2" and "fallback" in d.rationale
