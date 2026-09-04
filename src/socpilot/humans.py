"""Human-in-the-loop gateways.

The Responder asks a gateway for a decision on every gated action. Three
implementations cover the real deployment modes:

  InteractiveGateway  — a person answers in the terminal (a Slack bot or
                        ticket comment would play the same role in production)
  AutoGateway         — scripted approve/deny, for demos and tests
  DeferredGateway     — returns nothing; the incident is persisted in
                        AWAITING_APPROVAL and resumed later with
                        `socpilot decide <incident> <action> --approve|--deny`
"""
from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.panel import Panel

from .models import Approval, Incident, ProposedAction, utcnow


class AutoGateway:
    def __init__(self, approve: bool, approver: str = "auto-gateway (demo)", comment: str = ""):
        self.approve = approve
        self.approver = approver
        self.comment = comment or ("approved by scripted gateway" if approve else "denied by scripted gateway")

    def request(self, inc: Incident, act: ProposedAction) -> Optional[Approval]:
        return Approval(decided_at=utcnow(), approver=self.approver, approved=self.approve, comment=self.comment)


class DeferredGateway:
    def request(self, inc: Incident, act: ProposedAction) -> Optional[Approval]:
        return None


class InteractiveGateway:
    def __init__(self, console: Optional[Console] = None, approver: str = "analyst@console"):
        self.console = console or Console()
        self.approver = approver

    def request(self, inc: Incident, act: ProposedAction) -> Optional[Approval]:
        asset = act.params.get("host")
        self.console.print(Panel.fit(
            f"[bold yellow]Approval needed[/] — {inc.id}\n"
            f"[bold]{act.describe()}[/]\n"
            f"Why: {act.rationale}\n"
            f"Risk tier {act.risk_tier.value}: {act.policy_reason}\n"
            + (f"Business impact: {asset}\n" if asset else "")
            + "Done so far: " + ("; ".join(a.describe() for a in inc.executed_actions) or "nothing"),
            title="human decision", border_style="yellow",
        ))
        while True:
            ans = self.console.input("[bold]approve / deny / defer[/] › ").strip().lower()
            if ans in ("a", "approve", "y", "yes"):
                return Approval(decided_at=utcnow(), approver=self.approver, approved=True, comment="approved at console")
            if ans in ("d", "deny", "n", "no"):
                reason = self.console.input("reason › ").strip()
                return Approval(decided_at=utcnow(), approver=self.approver, approved=False, comment=reason or "denied at console")
            if ans in ("defer", "later", "skip"):
                return None
