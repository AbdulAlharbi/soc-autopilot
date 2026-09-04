"""Incident Commander — the orchestrator.

Owns the incident lifecycle:

    NEW → TRIAGED → (closed_false_positive | closed_benign)
                  → INVESTIGATING → PLANNING → CONTAINING
                       → AWAITING_APPROVAL (persist, resume later)
                       → CONTAINED → RESOLVED
                       → ESCALATED (a human said no, or containment failed)

It never calls a tool itself; it sequences the specialist agents, persists
state after every phase so a crash or a deferred approval can be resumed, and
decides when the workflow is done.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .agents.communicator import CommunicatorAgent
from .agents.investigator import InvestigatorAgent
from .agents.reporter import ReporterAgent
from .agents.responder import ApprovalGateway, ResponderAgent
from .agents.triage import TriageAgent
from .audit import AuditLog
from .config import Settings
from .llm.base import Brain, make_brain
from .models import ActionStatus, Alert, Incident, IncidentState, Verdict
from .policy import Policy
from .tools.environment import MockEnvironment
from .tools.registry import ToolRegistry
from .ui import NullUI


class IncidentStore:
    def __init__(self, directory: Path):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)

    def save(self, inc: Incident) -> Path:
        path = self.dir / f"{inc.id}.json"
        path.write_text(inc.model_dump_json(indent=1), encoding="utf-8")
        return path

    def load(self, incident_id: str) -> Incident:
        return Incident.model_validate_json((self.dir / f"{incident_id}.json").read_text(encoding="utf-8"))

    def list(self) -> list[Incident]:
        return [Incident.model_validate_json(p.read_text(encoding="utf-8")) for p in sorted(self.dir.glob("INC-*.json"))]


class IncidentCommander:
    name = "commander"

    def __init__(self, settings: Settings, gateway: ApprovalGateway, brain: Optional[Brain] = None,
                 env: Optional[MockEnvironment] = None, ui: Optional[NullUI] = None):
        self.settings = settings
        self.ui = ui or NullUI()
        self.env = env or MockEnvironment(settings.fixtures_dir)
        self.audit = AuditLog(settings.audit_path)
        self.tools = ToolRegistry(self.env, self.audit)
        self.policy = Policy.load(settings.policy_path)
        self.brain = brain or make_brain(settings.resolve_brain(), settings.model)
        self.gateway = gateway
        self.store = IncidentStore(settings.incidents_dir)
        deps = (self.brain, self.tools, self.env, self.audit, settings)
        self.triage = TriageAgent(*deps)
        self.investigator = InvestigatorAgent(*deps)
        self.responder = ResponderAgent(*deps, policy=self.policy)
        self.comms = CommunicatorAgent(*deps)
        self.reporter = ReporterAgent(*deps)

    # ------------------------------------------------------------------ #
    def _move(self, inc: Incident, state: IncidentState, note: str = "") -> None:
        inc.transition(state, self.name, note)
        self.audit.record(inc.id, self.name, "state", to=state.value, note=note)
        self._checkpoint(inc)

    def _checkpoint(self, inc: Incident) -> None:
        """Persist incident + world state so a crash or deferred approval can be resumed."""
        self.store.save(inc)
        self.env.save(self.settings.world_path)

    # ------------------------------------------------------------------ #
    def run(self, alert: Alert) -> Incident:
        inc = Incident(alert=alert, brain=self.brain.name)
        self.audit.record(inc.id, self.name, "incident_opened", alert=alert.id, rule=alert.rule, brain=self.brain.name)
        self.ui.phase(f"{inc.id}", alert.title)

        # 1. Triage --------------------------------------------------------
        self.ui.phase("Triage", "enrich → signals → verdict")
        inc.triage = self.triage.run(inc)
        t = inc.triage
        self._move(inc, IncidentState.TRIAGED, f"{t.verdict.value}/{t.severity.value}/{t.confidence} → {t.category}")
        self.ui.kv([("verdict", t.verdict.value), ("severity", t.severity.value), ("confidence", t.confidence),
                    ("category", t.category), ("mitre", ", ".join(t.mitre_techniques) or "-"), ("why", t.rationale)])
        self.comms.open_ticket(inc)

        if t.verdict == Verdict.FALSE_POSITIVE:
            return self._close_false_positive(inc)
        if t.verdict == Verdict.BENIGN:
            self._move(inc, IncidentState.CLOSED_BENIGN, "authorised activity")
            self.comms.close(inc, "Closed: authorised activity, no action required.")
            self.reporter.write(inc, self.settings.reports_dir)
            self._checkpoint(inc)
            self.ui.final(inc)
            return inc

        # 2. Investigate ---------------------------------------------------
        self._move(inc, IncidentState.INVESTIGATING)
        self.ui.phase("Investigation", "pivot → scope → timeline → root cause")
        inc.investigation = self.investigator.run(inc)
        inv = inc.investigation
        self.ui.kv([("hosts", ", ".join(inv.affected_hosts)), ("users", ", ".join(inv.affected_users)),
                    ("lateral", inv.lateral_movement), ("root cause", inv.root_cause), ("data at risk", inv.data_at_risk),
                    ("confidence", inv.confidence)])
        self.ui.bullets(inv.findings, "findings")
        self.comms.update(inc, f"Investigation: {len(inv.affected_hosts)} host(s), {len(inv.affected_users)} user(s), "
                               f"lateral={inv.lateral_movement}. Root cause: {inv.root_cause}")
        self._checkpoint(inc)

        # 3. Plan ----------------------------------------------------------
        self._move(inc, IncidentState.PLANNING)
        self.ui.phase("Response plan", "playbook → policy tiering → brain review")
        playbook, inc.actions = self.responder.plan(inc)
        self.ui.info(f"playbook [bold]{playbook.name}[/]: {playbook.description}")
        self.ui.actions(inc.actions)
        self._checkpoint(inc)
        inc.note(f"Playbook {playbook.name}; notify roles {[r['role'] for r in playbook.notify]}")

        # 4. Contain -------------------------------------------------------
        self._move(inc, IncidentState.CONTAINING)
        self.ui.phase("Containment", "auto-execute safe actions, gate the rest")
        done = self.responder.execute(inc, self.gateway, on_approval_request=self.comms.request_approval)
        self.comms.notify_stakeholders(inc, playbook.notify)
        self.ui.actions(inc.actions)
        if not done:
            self._move(inc, IncidentState.AWAITING_APPROVAL,
                       f"{len(inc.pending_actions)} action(s) waiting on a human; safe actions already executed")
            self.comms.update(inc, f"Paused: {len(inc.pending_actions)} action(s) awaiting approval in {self.settings.approvals_channel}. "
                                   f"Resume with `socpilot decide {inc.id} <action-id> --approve|--deny`.")
            self.ui.final(inc)
            return inc
        return self._finalise(inc)

    # ------------------------------------------------------------------ #
    def resume(self, inc: Incident) -> Incident:
        """Continue an incident that was paused for approvals."""
        if inc.state != IncidentState.AWAITING_APPROVAL:
            raise ValueError(f"{inc.id} is in state {inc.state.value}, nothing to resume")
        self.ui.phase(f"{inc.id}", "resuming after human decision")
        self._move(inc, IncidentState.CONTAINING, "resumed")
        done = self.responder.execute(inc, self.gateway, on_approval_request=self.comms.request_approval)
        self.ui.actions(inc.actions)
        if not done:
            self._move(inc, IncidentState.AWAITING_APPROVAL, f"{len(inc.pending_actions)} action(s) still pending")
            self.ui.final(inc)
            return inc
        return self._finalise(inc)

    # ------------------------------------------------------------------ #
    def _finalise(self, inc: Incident) -> Incident:
        denied = [a for a in inc.actions if a.status == ActionStatus.DENIED]
        failed = [a for a in inc.actions if a.status == ActionStatus.FAILED]
        unverified = [a for a in inc.executed_actions if a.verified is False]
        self.ui.phase("Wrap-up", "verify → report → close or escalate")
        if denied or failed or unverified:
            why = []
            if denied:
                why.append(f"{len(denied)} containment action(s) denied by human ({'; '.join(a.describe() for a in denied)})")
            if failed:
                why.append(f"{len(failed)} action(s) failed")
            if unverified:
                why.append(f"{len(unverified)} action(s) could not be verified")
            self._move(inc, IncidentState.ESCALATED, "; ".join(why))
            self.comms.update(inc, f":warning: Escalated to IR lead — {'; '.join(why)}. "
                                   f"{len(inc.executed_actions)} action(s) remain in place; residual risk documented in the report.")
            self.comms.notify_stakeholders(inc, [{"role": "ir_lead"}])
            inc.note("Escalated: containment incomplete (human denial, failure or unverifiable action); residual risk documented.")
        else:
            self._move(inc, IncidentState.CONTAINED, f"{len(inc.executed_actions)} action(s) executed and verified")
            self.comms.update(inc, f"Contained: {len(inc.executed_actions)} action(s) executed and verified.")
            self._move(inc, IncidentState.RESOLVED, "contained; report written; ticket resolved pending post-incident review")
        path = self.reporter.write(inc, self.settings.reports_dir)
        if inc.state == IncidentState.RESOLVED:
            self.comms.close(inc, f"Contained autonomously. Report: {path.name}. Post-incident review scheduled.")
        else:
            self.comms.update(inc, f"Report: {path.name}")
        self._checkpoint(inc)
        self.ui.final(inc)
        return inc

    def _close_false_positive(self, inc: Incident) -> Incident:
        # even a false positive produces work: tune the detection so it does not fire again
        self._move(inc, IncidentState.PLANNING, "false positive — routing tuning request")
        playbook, inc.actions = self.responder.plan(inc)
        self.ui.actions(inc.actions)
        self.responder.execute(inc, self.gateway, on_approval_request=self.comms.request_approval)
        self.ui.actions(inc.actions)
        self._move(inc, IncidentState.CLOSED_FALSE_POSITIVE, "detection misfire on authorised activity")
        tuning = [a.result.get("ticket_id") for a in inc.executed_actions if a.key == "ticketing.create_ticket" and a.result]
        self.comms.close(inc, f"False positive: {inc.triage.rationale if inc.triage else ''}"
                              + (f" Tuning ticket {tuning[0]} raised with detection engineering." if tuning else ""))
        self.reporter.write(inc, self.settings.reports_dir)
        self._checkpoint(inc)
        self.ui.final(inc)
        return inc


# ---------------------------------------------------------------------- #
def load_scenario(path: Path) -> tuple[Alert, dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return Alert.model_validate(raw["alert"]), raw
