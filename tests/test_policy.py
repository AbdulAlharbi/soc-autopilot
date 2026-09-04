"""The autonomy policy is the safety boundary — pin its behaviour."""
from socpilot.audit import AuditLog
from socpolicy_helpers import make_incident  # noqa: F401  (helper module below)
from socpilot.models import ProposedAction, RiskTier, TriageResult, Severity, Verdict
from socpilot.policy import Policy, assess
from socpilot.tools.environment import MockEnvironment


def _inc(settings, confidence=0.9):
    inc = make_incident(settings)
    inc.triage = TriageResult(verdict=Verdict.TRUE_POSITIVE, severity=Severity.HIGH, confidence=confidence,
                              category="malware_c2", rationale="test")
    return inc


def test_workstation_isolation_is_autonomous(settings):
    env, pol = MockEnvironment(settings.fixtures_dir), Policy.load(settings.policy_path)
    v = assess(ProposedAction(tool="edr", operation="isolate_host", params={"host": "WS-ENG-042"}), _inc(settings), env, pol, 0)
    assert v.tier == RiskTier.MEDIUM and not v.requires_approval


def test_production_server_isolation_needs_a_human(settings):
    env, pol = MockEnvironment(settings.fixtures_dir), Policy.load(settings.policy_path)
    v = assess(ProposedAction(tool="edr", operation="isolate_host", params={"host": "SRV-ERP-01"}), _inc(settings), env, pol, 0)
    assert v.tier == RiskTier.HIGH and v.requires_approval
    assert "critical asset" in v.reason and "production" in v.reason


def test_low_tier_actions_are_not_bumped_by_asset(settings):
    env, pol = MockEnvironment(settings.fixtures_dir), Policy.load(settings.policy_path)
    v = assess(ProposedAction(tool="edr", operation="kill_process", params={"host": "SRV-ERP-01", "pid": 1}), _inc(settings), env, pol, 0)
    assert v.tier == RiskTier.LOW and not v.requires_approval


def test_disable_user_always_requires_approval(settings):
    env, pol = MockEnvironment(settings.fixtures_dir), Policy.load(settings.policy_path)
    v = assess(ProposedAction(tool="iam", operation="disable_user", params={"user": "a.khan"}), _inc(settings), env, pol, 0)
    assert v.requires_approval and "always" in v.reason


def test_privileged_user_bumps_tier(settings):
    env, pol = MockEnvironment(settings.fixtures_dir), Policy.load(settings.policy_path)
    v = assess(ProposedAction(tool="iam", operation="revoke_sessions_and_reset_password", params={"user": "r.otaibi"}), _inc(settings), env, pol, 0)
    assert v.tier == RiskTier.HIGH and v.requires_approval


def test_low_confidence_blocks_automation(settings):
    env, pol = MockEnvironment(settings.fixtures_dir), Policy.load(settings.policy_path)
    v = assess(ProposedAction(tool="firewall", operation="block_ip", params={"ip": "1.2.3.4"}), _inc(settings, confidence=0.5), env, pol, 0)
    assert v.requires_approval and "confidence" in v.reason


def test_automation_budget(settings):
    env, pol = MockEnvironment(settings.fixtures_dir), Policy.load(settings.policy_path)
    v = assess(ProposedAction(tool="firewall", operation="block_ip", params={"ip": "1.2.3.4"}), _inc(settings), env, pol, pol.max_auto_actions_per_incident)
    assert v.requires_approval and "budget" in v.reason


def test_never_automate_is_absolute(settings):
    env, pol = MockEnvironment(settings.fixtures_dir), Policy.load(settings.policy_path)
    v = assess(ProposedAction(tool="edr", operation="wipe_host", params={"host": "WS-ENG-042"}), _inc(settings), env, pol, 0)
    assert v.requires_approval and "never" in v.reason
