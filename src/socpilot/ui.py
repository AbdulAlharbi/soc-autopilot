"""Console output for the orchestrator. `NullUI` keeps tests quiet."""
from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import ActionStatus, Incident, ProposedAction

TIER_COLOR = {0: "dim", 1: "green", 2: "yellow", 3: "red"}


class NullUI:
    def phase(self, title: str, subtitle: str = "") -> None: ...
    def info(self, text: str) -> None: ...
    def kv(self, rows: list[tuple[str, Any]], title: str = "") -> None: ...
    def actions(self, actions: list[ProposedAction]) -> None: ...
    def bullets(self, items: list[str], title: str = "") -> None: ...
    def final(self, inc: Incident) -> None: ...
    def chat(self, messages: list[dict[str, Any]]) -> None: ...


class RichUI(NullUI):
    def __init__(self, console: Console | None = None):
        self.c = console or Console()

    def phase(self, title: str, subtitle: str = "") -> None:
        self.c.rule(f"[bold cyan]{title}[/]" + (f"  [dim]{subtitle}[/]" if subtitle else ""))

    def info(self, text: str) -> None:
        self.c.print(text)

    def kv(self, rows: list[tuple[str, Any]], title: str = "") -> None:
        t = Table(show_header=False, box=None, padding=(0, 1), title=title, title_justify="left")
        for k, v in rows:
            t.add_row(f"[bold]{k}[/]", str(v))
        self.c.print(t)

    def bullets(self, items: list[str], title: str = "") -> None:
        if title:
            self.c.print(f"[bold]{title}[/]")
        for i in items:
            self.c.print(f"  • {i}")

    def actions(self, actions: list[ProposedAction]) -> None:
        t = Table(box=None, padding=(0, 1))
        for col in ("id", "action", "tier", "gate", "status", "verified", "policy"):
            t.add_column(col)
        for a in actions:
            gate = "[red]human[/]" if a.requires_approval else "[green]auto[/]"
            status = {
                ActionStatus.EXECUTED: "[green]executed[/]", ActionStatus.DENIED: "[red]denied[/]",
                ActionStatus.AWAITING_APPROVAL: "[yellow]awaiting[/]", ActionStatus.FAILED: "[red]failed[/]",
                ActionStatus.SKIPPED: "[dim]skipped[/]",
            }.get(a.status, a.status.value)
            ver = {True: "[green]✓[/]", False: "[red]✗[/]", None: "[dim]–[/]"}[a.verified]
            t.add_row(a.id, a.describe(), f"[{TIER_COLOR[a.risk_tier.value]}]{a.risk_tier.value}[/]", gate, status, ver,
                      f"[dim]{a.policy_reason[:70]}[/]")
        self.c.print(t)

    def final(self, inc: Incident) -> None:
        color = {"resolved": "green", "closed_false_positive": "green", "closed_benign": "green",
                 "awaiting_approval": "yellow", "escalated": "red"}.get(inc.state.value, "white")
        exec_n = len(inc.executed_actions)
        auto_n = sum(1 for a in inc.executed_actions if not a.requires_approval)
        self.c.print(Panel.fit(
            f"[bold {color}]{inc.state.value.upper()}[/]  {inc.id}\n"
            f"{exec_n} action(s) executed ({auto_n} autonomous, {exec_n - auto_n} human-approved) · "
            f"{len(inc.pending_actions)} pending · {sum(1 for a in inc.actions if a.status == ActionStatus.DENIED)} denied\n"
            f"{len(inc.communications)} communication(s) · ticket {inc.ticket_id} · report {inc.report_path or '-'}",
            border_style=color,
        ))

    def chat(self, messages: list[dict[str, Any]]) -> None:
        if not messages:
            return
        self.c.rule("[bold]chat transcript[/]")
        for m in messages:
            self.c.print(f"[bold blue]{m['channel']}[/] [dim]{m['ts'][11:19]}[/]\n{m['text']}\n")
