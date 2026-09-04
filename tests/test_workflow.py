"""End-to-end: every bundled scenario reaches its expected terminal state with the heuristic brain."""
import json

import pytest

from socpilot.audit import AuditLog
from socpilot.commander import IncidentCommander, IncidentStore, load_scenario
from socpilot.humans import AutoGateway, DeferredGateway
from socpilot.models import ActionStatus, Approval, IncidentState, utcnow
from socpilot.tools.environment import MockEnvironment

SCENARIOS = ["phishing-credential-theft", "beacon-c2-workstation", "port-scan-false-positive", "ransomware-precursor-server"]


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenario_reaches_expected_state(settings, name):
    alert, raw = load_scenario(settings.scenarios_dir / f"{name}.json")
    inc = IncidentCommander(settings, gateway=AutoGateway(True)).run(alert)
    exp = raw["expected"]
    assert inc.triage.verdict.value == exp["verdict"]
    assert inc.triage.category == exp["category"]
    assert inc.state.value == (exp.get("final_state") or exp.get("final_state_if_approved"))
    assert not inc.pending_actions
    # every executed action that can be verified, was
    assert all(a.verified in (True, None) for a in inc.executed_actions)
    assert inc.report_path and inc.ticket_id
    ok, n = AuditLog(settings.audit_path).verify()
    assert ok and n > 10


def test_false_positive_takes_no_containment_action(settings):
    alert, _ = load_scenario(settings.scenarios_dir / "port-scan-false-positive.json")
    cmd = IncidentCommander(settings, gateway=AutoGateway(True))
    inc = cmd.run(alert)
    assert inc.state == IncidentState.CLOSED_FALSE_POSITIVE
    assert inc.investigation is None
    assert all(a.key == "ticketing.create_ticket" for a in inc.executed_actions)
    assert not cmd.env.firewall.blocked and not any(h["isolated"] for h in cmd.env.edr.hosts.values())
    assert any(t["queue"] == "detection-engineering" for t in cmd.env.ticketing.tickets.values())


def test_phishing_is_fully_autonomous_and_contains_campaign(settings):
    alert, _ = load_scenario(settings.scenarios_dir / "phishing-credential-theft.json")
    cmd = IncidentCommander(settings, gateway=AutoGateway(False))  # a denying human must never be consulted
    inc = cmd.run(alert)
    assert inc.state == IncidentState.RESOLVED
    assert not any(a.requires_approval for a in inc.actions)
    env = cmd.env
    assert "j.alrashid" in env.iam.reset and "j.alrashid" in env.iam.mfa_reset
    assert "197.210.53.14" in env.firewall.blocked
    assert {m["status"] for m in env.email.messages if m["sender"].endswith("invoice-secure-portal.com")} == {"quarantined"}
    assert not any(c["type"] == "mailbox_rule_created" for c in env.iam.users["j.alrashid"]["recent_changes"])
    assert any(m["to"] == "j.alrashid@corp.example" for m in env.mail.sent)
    assert any(m["to"] == "m.hassan@corp.example" for m in env.mail.sent)  # manager notified


def test_ransomware_gates_business_impacting_actions(settings):
    alert, _ = load_scenario(settings.scenarios_dir / "ransomware-precursor-server.json")
    cmd = IncidentCommander(settings, gateway=AutoGateway(False, approver="f.zahrani", comment="change freeze"))
    inc = cmd.run(alert)
    assert inc.state == IncidentState.ESCALATED
    gated = {a.describe() for a in inc.actions if a.requires_approval}
    assert "edr.isolate_host(host=SRV-ERP-01)" in gated and "iam.disable_user(user=svc_backup)" in gated
    auto = {a.key for a in inc.executed_actions if not a.requires_approval}
    assert {"edr.kill_process", "firewall.block_ip", "edr.collect_forensics"} <= auto
    assert cmd.env.edr.hosts["WS-IT-ADM-03"]["isolated"] and not cmd.env.edr.hosts["SRV-ERP-01"]["isolated"]
    assert "svc_backup" not in cmd.env.iam.disabled
    assert any(m["channel"] == settings.approvals_channel for m in cmd.env.chat.messages)
    assert any(m["to"] == settings.ir_lead for m in cmd.env.mail.sent)
    assert "r.otaibi" in inc.investigation.affected_users and inc.investigation.lateral_movement


def test_deferred_approval_persists_and_resumes(settings):
    alert, _ = load_scenario(settings.scenarios_dir / "ransomware-precursor-server.json")
    cmd = IncidentCommander(settings, gateway=DeferredGateway())
    inc = cmd.run(alert)
    assert inc.state == IncidentState.AWAITING_APPROVAL and inc.pending_actions
    assert settings.world_path.exists()

    # a brand-new process picks the incident up later
    store = IncidentStore(settings.incidents_dir)
    inc2 = store.load(inc.id)
    for a in inc2.pending_actions:
        a.approval = Approval(decided_at=utcnow(), approver="f.zahrani", approved=True, comment="go")
    store.save(inc2)
    env = MockEnvironment.load(settings.fixtures_dir, settings.world_path)
    assert env.edr.hosts["WS-IT-ADM-03"]["isolated"]  # earlier autonomous work survived
    cmd2 = IncidentCommander(settings, gateway=DeferredGateway(), env=env)
    inc3 = cmd2.resume(inc2)
    assert inc3.state == IncidentState.RESOLVED
    assert all(a.status == ActionStatus.EXECUTED for a in inc3.actions if a.requires_approval)
    assert env.edr.hosts["SRV-ERP-01"]["isolated"] and "svc_backup" in env.iam.disabled


def test_audit_chain_detects_tampering(settings):
    alert, _ = load_scenario(settings.scenarios_dir / "beacon-c2-workstation.json")
    IncidentCommander(settings, gateway=AutoGateway(True)).run(alert)
    log = AuditLog(settings.audit_path)
    assert log.verify()[0]
    lines = settings.audit_path.read_text().splitlines()
    entry = json.loads(lines[5])
    entry["payload"]["tool"] = "edr.unisolate_host"  # rewrite history
    lines[5] = json.dumps(entry)
    settings.audit_path.write_text("\n".join(lines) + "\n")
    assert not AuditLog(settings.audit_path).verify()[0]
