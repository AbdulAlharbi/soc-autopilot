"""socpilot command-line interface."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .commander import IncidentCommander, IncidentStore, load_scenario
from .config import Settings
from .humans import AutoGateway, DeferredGateway, InteractiveGateway
from .models import ActionStatus, Approval, utcnow
from .tools.environment import MockEnvironment
from .ui import RichUI

app = typer.Typer(help="SOC Autopilot — autonomous multi-agent security incident triage & response.", no_args_is_help=True)
console = Console()


def _settings(brain: Optional[str], out: Optional[Path]) -> Settings:
    s = Settings()
    if brain:
        s.brain = brain
    if out:
        s.out_dir = out
    return s


def _gateway(mode: str):
    return {"interactive": lambda: InteractiveGateway(console),
            "approve": lambda: AutoGateway(True),
            "deny": lambda: AutoGateway(False, comment="ERP change freeze — cannot take the server offline during month-end close"),
            "defer": DeferredGateway}[mode]()


BrainOpt = typer.Option(None, "--brain", "-b", help="claude | heuristic | auto (default: claude if ANTHROPIC_API_KEY is set)")
ApprovalOpt = typer.Option("interactive", "--approvals", "-a", help="interactive | approve | deny | defer")
OutOpt = typer.Option(None, "--out", help="Output directory (default: ./out)")


@app.command()
def scenarios() -> None:
    """List the bundled alert scenarios."""
    s = Settings()
    t = Table("name", "alert", "expected", "description")
    for p in sorted(s.scenarios_dir.glob("*.json")):
        raw = json.loads(p.read_text())
        exp = raw.get("expected", {})
        t.add_row(raw["name"], raw["alert"]["rule"], exp.get("final_state") or f"approved→{exp.get('final_state_if_approved')} / denied→{exp.get('final_state_if_denied')}", raw["description"])
    console.print(t)


@app.command()
def run(scenario: str = typer.Argument(..., help="Scenario name (see `scenarios`) or path to an alert JSON"),
        brain: Optional[str] = BrainOpt, approvals: str = ApprovalOpt, out: Optional[Path] = OutOpt,
        show_chat: bool = typer.Option(True, help="Print the chat transcript at the end")) -> None:
    """Run the full agent workflow on one alert."""
    s = _settings(brain, out)
    path = Path(scenario) if scenario.endswith(".json") else s.scenarios_dir / f"{scenario}.json"
    if not path.exists():
        raise typer.BadParameter(f"scenario not found: {path}")
    alert, raw = load_scenario(path)
    ui = RichUI(console)
    cmd = IncidentCommander(s, gateway=_gateway(approvals), ui=ui)
    console.print(f"[dim]brain={cmd.brain.name} · approvals={approvals} · policy={s.policy_path.name}[/]")
    inc = cmd.run(alert)
    if show_chat:
        ui.chat(cmd.env.chat.transcript())
    _expectation(raw, inc, approvals)


@app.command("run-all")
def run_all(brain: Optional[str] = BrainOpt, approvals: str = typer.Option("approve", "--approvals", "-a"), out: Optional[Path] = OutOpt) -> None:
    """Run every bundled scenario back to back (non-interactive)."""
    s = _settings(brain, out)
    summary = Table("scenario", "incident", "verdict", "severity", "final state", "auto", "human", "denied")
    for p in sorted(s.scenarios_dir.glob("*.json")):
        alert, raw = load_scenario(p)
        cmd = IncidentCommander(s, gateway=_gateway(approvals), ui=RichUI(console))
        inc = cmd.run(alert)
        ex = inc.executed_actions
        summary.add_row(raw["name"], inc.id, inc.triage.verdict.value, inc.triage.severity.value, inc.state.value,
                        str(sum(1 for a in ex if not a.requires_approval)), str(sum(1 for a in ex if a.requires_approval)),
                        str(sum(1 for a in inc.actions if a.status == ActionStatus.DENIED)))
    console.rule("[bold]summary[/]")
    console.print(summary)


@app.command()
def decide(incident_id: str, action_id: str,
           approve: bool = typer.Option(False, "--approve/--deny", help="Approve or deny the gated action"),
           approver: str = typer.Option("analyst@cli", "--as"), comment: str = typer.Option("", "--comment", "-c"),
           brain: Optional[str] = BrainOpt, out: Optional[Path] = OutOpt) -> None:
    """Record a human decision on a deferred action and resume the incident."""
    s = _settings(brain, out)
    store = IncidentStore(s.incidents_dir)
    inc = store.load(incident_id)
    act = inc.get_action(action_id)
    if act.status != ActionStatus.AWAITING_APPROVAL:
        raise typer.BadParameter(f"{action_id} is {act.status.value}, not awaiting approval")
    act.approval = Approval(requested_at=act.approval.requested_at if act.approval else utcnow(),
                            decided_at=utcnow(), approver=approver, approved=approve, comment=comment)
    store.save(inc)
    ui = RichUI(console)
    env = MockEnvironment.load(s.fixtures_dir, s.world_path)   # the world as the agents left it
    cmd = IncidentCommander(s, gateway=DeferredGateway(), ui=ui, env=env)
    inc = cmd.resume(inc)
    ui.chat(cmd.env.chat.transcript())


@app.command()
def show(incident_id: str, out: Optional[Path] = OutOpt) -> None:
    """Print an incident's current state and actions."""
    s = _settings(None, out)
    inc = IncidentStore(s.incidents_dir).load(incident_id)
    ui = RichUI(console)
    ui.kv([("state", inc.state.value), ("alert", inc.alert.title), ("ticket", inc.ticket_id),
           ("verdict", inc.triage.verdict.value if inc.triage else "-"), ("report", inc.report_path)])
    ui.actions(inc.actions)


@app.command()
def audit(incident_id: Optional[str] = typer.Argument(None), out: Optional[Path] = OutOpt) -> None:
    """Show the audit trail (optionally for one incident) and verify the hash chain."""
    from .audit import AuditLog

    s = _settings(None, out)
    log = AuditLog(s.audit_path)
    t = Table("ts", "incident", "actor", "event", "detail")
    for e in log.entries(incident_id):
        detail = json.dumps(e["payload"], default=str)
        t.add_row(e["ts"][11:19], e["incident"], e["actor"], e["event"], detail[:110] + ("…" if len(detail) > 110 else ""))
    console.print(t)
    ok, n = log.verify()
    console.print(f"chain {'[green]valid[/]' if ok else '[red]BROKEN[/]'} · {n} entries")


# ---------------------------------------------------------------------- #
def _expectation(raw: dict, inc, approvals: str) -> None:
    exp = raw.get("expected") or {}
    want = exp.get("final_state") or (exp.get("final_state_if_denied") if approvals == "deny" else exp.get("final_state_if_approved"))
    if want and approvals != "defer":
        ok = inc.state.value == want
        console.print(f"expected [bold]{want}[/] → {'[green]match[/]' if ok else f'[red]got {inc.state.value}[/]'}")


if __name__ == "__main__":
    app()
