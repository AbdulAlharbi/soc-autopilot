"""Responder agent — the only agent with write authority.

Planning:  a category playbook (YAML) is expanded against the investigation
           context into concrete actions; every action is assessed by the
           autonomy policy; the brain may prune or add actions from the tool
           catalogue (adds are policy-assessed too — the LLM cannot smuggle
           in an unreviewed high-tier action).
Execution: safe actions run immediately; gated actions are sent to a human
           through the approval gateway. Approvals can be synchronous (CLI)
           or deferred (state is persisted and resumed later).
Verification: after execution the agent re-queries the system to confirm the
           action actually took effect.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml

from ..models import ActionStatus, Approval, Incident, ProposedAction, ResponseDecision, RiskTier
from ..policy import Policy, assess, count_auto_actions
from .base import BaseAgent

PLAN_SYSTEM = """You are reviewing a proposed containment plan produced from a playbook.
Drop actions that are unnecessary or that the evidence does not support (give the reason). Add actions only if they are clearly justified by the findings and exist in the tool catalogue.
You cannot bypass the autonomy policy: any action you add will be risk-assessed and may require human approval."""

PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_\.]*)\}")


class Playbook:
    def __init__(self, raw: dict[str, Any]):
        self.name: str = raw["name"]
        self.description: str = raw.get("description", "")
        self.mitre: list[str] = raw.get("mitre", [])
        self.notify: list[dict[str, str]] = raw.get("notify", [])
        self.actions: list[dict[str, Any]] = raw.get("actions", [])

    @classmethod
    def load(cls, directory: Path, category: str) -> "Playbook":
        path = directory / f"{category}.yaml"
        if not path.exists():
            path = directory / "generic_suspicious.yaml"
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))


def _lookup(ctx: dict[str, Any], dotted: str) -> Any:
    cur: Any = ctx
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _render(value: Any, ctx: dict[str, Any]) -> tuple[Any, bool]:
    """Render a param template. Returns (value, ok). ok=False if a placeholder is unresolved."""
    if not isinstance(value, str):
        return value, True
    m = PLACEHOLDER.fullmatch(value)
    if m:  # whole value is one placeholder → keep native type
        v = _lookup(ctx, m.group(1))
        return v, v not in (None, "", [])
    ok = True

    def sub(match: re.Match) -> str:
        nonlocal ok
        v = _lookup(ctx, match.group(1))
        if v in (None, "", []):
            ok = False
            return ""
        return str(v)

    return PLACEHOLDER.sub(sub, value), ok


def expand_action(spec: dict[str, Any], ctx: dict[str, Any]) -> list[ProposedAction]:
    if spec.get("when") and not _lookup(ctx, spec["when"]):
        return []
    params: dict[str, Any] = dict(spec.get("params", {}))
    each = [(k, v[len("{each:"):-1]) for k, v in params.items() if isinstance(v, str) and v.startswith("{each:")]
    variants: list[dict[str, Any]]
    if each:
        k, key = each[0]
        values = _lookup(ctx, key) or []
        variants = [dict(params, **{k: v}) for v in values]
    else:
        variants = [params]
    out = []
    for variant in variants:
        rendered, ok = {}, True
        for pk, pv in variant.items():
            val, good = _render(pv, ctx)
            ok = ok and good
            rendered[pk] = val
        if ok:
            out.append(ProposedAction(tool=spec["tool"], operation=spec["operation"], params=rendered,
                                      rationale=spec.get("rationale", ""), reversible=spec.get("reversible", True)))
    return out


class ResponderAgent(BaseAgent):
    name = "responder"
    can_write = True

    def __init__(self, *args: Any, policy: Policy, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.policy = policy

    # ------------------------------------------------------------------ #
    def build_context(self, inc: Incident) -> dict[str, Any]:
        a = inc.alert
        ctx: dict[str, Any] = {
            "user": a.user, "host": a.host, "src_ip": a.src_ip, "dst_ip": a.dst_ip, "alert_rule": a.rule,
            "affected_hosts": [a.host] if a.host else [], "malicious_ips": [], "malicious_pids": [],
            "campaign_message_ids": [], "oauth_app_ids": [], "compromised_users": [],
            "signals": inc.triage.signals if inc.triage else {},
        }
        ctx.update({k: v for k, v in ctx["signals"].items() if k.startswith("allowlist_")})
        if inc.investigation:
            ctx.update(inc.investigation.context)
        return ctx

    def _assess(self, action: ProposedAction, inc: Incident) -> None:
        verdict = assess(action, inc, self.env, self.policy, count_auto_actions(inc))
        action.risk_tier = verdict.tier
        action.requires_approval = verdict.requires_approval
        action.policy_reason = verdict.reason

    def plan(self, inc: Incident) -> tuple[Playbook, list[ProposedAction]]:
        assert inc.triage is not None
        playbook = Playbook.load(self.settings.playbooks_dir, inc.triage.category)
        ctx = self.build_context(inc)
        actions: list[ProposedAction] = []
        seen: set[str] = set()
        for spec in playbook.actions:
            for act in expand_action(spec, ctx):
                if act.describe() not in seen:
                    seen.add(act.describe())
                    actions.append(act)
        for act in actions:
            self._assess(act, inc)

        decision = self.brain.decide("plan_response", {
            "incident": {"id": inc.id, "title": inc.alert.title, "triage": inc.triage.model_dump(mode="json", exclude={"evidence", "signals"}),
                         "investigation": inc.investigation.model_dump(mode="json", exclude={"evidence", "timeline", "context"}) if inc.investigation else None},
            "playbook": {"name": playbook.name, "description": playbook.description},
            "proposed_actions": [dict(id=a.id, action=a.describe(), rationale=a.rationale, risk_tier=a.risk_tier.value,
                                      requires_approval=a.requires_approval, policy_reason=a.policy_reason) for a in actions],
            "tool_catalogue": self.tools.catalogue(read_only=False),
            "policy": {"auto_execute_max_tier": self.policy.auto_execute_max_tier},
        }, ResponseDecision, system=PLAN_SYSTEM)

        for act in actions:
            if act.id in decision.drop:
                act.status = ActionStatus.SKIPPED
                act.result = {"skipped_reason": decision.drop[act.id]}
        for add in decision.add:
            name = f"{add.tool}.{add.operation}"
            if not self.tools.has(name) or self.tools.spec(name).read_only:
                self.log(inc, "plan_add_rejected", tool=name, reason="not in containment catalogue")
                continue
            act = ProposedAction(tool=add.tool, operation=add.operation, params=add.params, rationale=f"[brain] {add.rationale}")
            self._assess(act, inc)
            actions.append(act)
        self.log(inc, "plan_built", playbook=playbook.name, brain=self.brain.name, rationale=decision.rationale,
                 actions=[dict(id=a.id, action=a.describe(), tier=a.risk_tier.value, approval=a.requires_approval, status=a.status.value) for a in actions])
        return playbook, actions

    # ------------------------------------------------------------------ #
    def execute(self, inc: Incident, gateway: "ApprovalGateway", on_approval_request=None) -> bool:
        """Run everything that is runnable. Returns True when no action is left waiting on a human."""
        # 1. everything the policy lets us do on our own, immediately
        for act in inc.actions:
            if act.status == ActionStatus.PROPOSED and not act.requires_approval:
                self._run(inc, act)
        # 2. gated actions
        for act in inc.actions:
            if act.status in (ActionStatus.PROPOSED, ActionStatus.AWAITING_APPROVAL) and act.requires_approval:
                if act.approval and act.approval.approved is not None:
                    self._apply_decision(inc, act)
                    continue
                if act.status == ActionStatus.PROPOSED:
                    act.status = ActionStatus.AWAITING_APPROVAL
                    act.approval = Approval()
                    if on_approval_request:
                        on_approval_request(inc, act)
                    self.log(inc, "approval_requested", action=act.id, describe=act.describe(), tier=act.risk_tier.value, reason=act.policy_reason)
                decision = gateway.request(inc, act)
                if decision is None:
                    continue  # deferred — will resume later
                act.approval = decision
                self._apply_decision(inc, act)
            elif act.status == ActionStatus.APPROVED:
                self._run(inc, act)
        return not inc.pending_actions

    def _apply_decision(self, inc: Incident, act: ProposedAction) -> None:
        assert act.approval is not None
        self.log(inc, "approval_decided", action=act.id, approved=act.approval.approved, approver=act.approval.approver, comment=act.approval.comment)
        if act.approval.approved:
            act.status = ActionStatus.APPROVED
            self._run(inc, act)
        else:
            act.status = ActionStatus.DENIED

    def _run(self, inc: Incident, act: ProposedAction) -> None:
        try:
            act.result = self.call(act.key, inc, **act.params)
            act.status = ActionStatus.EXECUTED
            act.verified = self._verify(act)
            self.log(inc, "action_executed", action=act.id, describe=act.describe(), verified=act.verified)
        except Exception as exc:  # noqa: BLE001
            act.status = ActionStatus.FAILED
            act.result = {"error": str(exc)}
            self.log(inc, "action_failed", action=act.id, describe=act.describe(), error=str(exc))

    def _verify(self, act: ProposedAction) -> Optional[bool]:
        env = self.env
        p = act.params
        if act.key == "edr.isolate_host":
            return bool(env.edr.hosts.get(p["host"], {}).get("isolated"))
        if act.key == "edr.kill_process":
            return all(pr["pid"] != int(p["pid"]) for pr in env.edr.hosts.get(p["host"], {}).get("processes", []))
        if act.key == "iam.disable_user":
            return p["user"] in env.iam.disabled
        if act.key == "iam.revoke_sessions_and_reset_password":
            return p["user"] in env.iam.reset
        if act.key == "iam.enforce_mfa_reregistration":
            return p["user"] in env.iam.mfa_reset
        if act.key == "iam.remove_mailbox_rules":
            return not any(c["type"] == "mailbox_rule_created" for c in env.iam.users[p["user"]].get("recent_changes", []))
        if act.key == "iam.revoke_oauth_grant":
            return not any(c.get("ref") == p["app_id"] for c in env.iam.users[p["user"]].get("recent_changes", []))
        if act.key == "firewall.block_ip":
            return p["ip"] in env.firewall.blocked
        if act.key == "email_gateway.quarantine_message":
            return any(m["message_id"] == p["message_id"] and m["status"] == "quarantined" for m in env.email.messages)
        if act.key == "ticketing.create_ticket":
            return bool(act.result and act.result.get("ticket_id") in env.ticketing.tickets)
        return None  # nothing to verify against


class ApprovalGateway:  # interface, implemented in humans.py
    def request(self, inc: Incident, act: ProposedAction) -> Optional[Approval]:  # pragma: no cover
        raise NotImplementedError
