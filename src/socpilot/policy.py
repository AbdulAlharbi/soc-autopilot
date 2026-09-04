"""Autonomy policy.

The policy is the contract between the organisation and the agents: it says
which actions may be executed autonomously and which need a human. It is
deliberately *not* something the LLM can reason its way around — every action
passes through `assess()` regardless of who proposed it.

Tiering logic:
    1. every tool operation has a base risk tier (config/policy.yaml)
    2. the tier is bumped when the target is a critical/production asset or a
       privileged / VIP / service account
    3. the action is auto-executable only if its final tier is at or below the
       autonomy ceiling, triage confidence is high enough, and the per-incident
       budget of automated actions has not been exhausted
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, Field

from .models import ActionStatus, ProposedAction, RiskTier, Severity

if TYPE_CHECKING:  # pragma: no cover
    from .models import Incident
    from .tools.environment import MockEnvironment


class Policy(BaseModel):
    auto_execute_max_tier: int = 2
    min_confidence_for_auto: float = 0.75
    max_auto_actions_per_incident: int = 10
    critical_asset_bump: int = 1
    production_env_bump: int = 1
    privileged_user_bump: int = 1
    service_account_bump: int = 1
    vip_user_bump: int = 1
    bump_min_base_tier: int = 2   # asset/identity bumps only escalate already-disruptive actions
    always_require_approval: list[str] = Field(default_factory=list)
    never_automate: list[str] = Field(default_factory=list)
    base_tiers: dict[str, int] = Field(default_factory=dict)
    host_params: list[str] = Field(default_factory=lambda: ["host", "hostname"])
    user_params: list[str] = Field(default_factory=lambda: ["user", "username", "account"])

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return cls(**raw)


class PolicyVerdict(BaseModel):
    tier: RiskTier
    requires_approval: bool
    reason: str


def assess(
    action: ProposedAction,
    incident: "Incident",
    env: "MockEnvironment",
    policy: Policy,
    auto_actions_so_far: int,
) -> PolicyVerdict:
    key = action.key
    base = policy.base_tiers.get(key)
    if base is None:
        base = policy.base_tiers.get(f"{action.tool}.*", RiskTier.HIGH.value)
    tier = int(base)
    reasons: list[str] = [f"base tier {tier} for {key}"]

    bumpable = tier >= policy.bump_min_base_tier

    # Asset-aware bump
    for p in policy.host_params if bumpable else []:
        host = action.params.get(p)
        if host:
            asset = env.assets.get(host) or {}
            if asset.get("criticality") == "critical":
                tier += policy.critical_asset_bump
                reasons.append(f"{host} is a critical asset (+{policy.critical_asset_bump})")
            if asset.get("environment") == "production":
                tier += policy.production_env_bump
                reasons.append(f"{host} is in production (+{policy.production_env_bump})")

    # Identity-aware bump
    for p in policy.user_params if bumpable else []:
        user = action.params.get(p)
        if user:
            profile = env.iam.get_user(user) or {}
            if profile.get("privileged"):
                tier += policy.privileged_user_bump
                reasons.append(f"{user} is privileged (+{policy.privileged_user_bump})")
            if profile.get("account_type") == "service":
                tier += policy.service_account_bump
                reasons.append(f"{user} is a service account (+{policy.service_account_bump})")
            if profile.get("vip"):
                tier += policy.vip_user_bump
                reasons.append(f"{user} is VIP (+{policy.vip_user_bump})")

    tier = min(tier, RiskTier.HIGH.value)
    final = RiskTier(tier)

    if key in policy.never_automate:
        return PolicyVerdict(tier=final, requires_approval=True, reason="never automated by policy")
    if key in policy.always_require_approval:
        return PolicyVerdict(tier=final, requires_approval=True, reason="always requires approval by policy")
    if final == RiskTier.READ_ONLY:
        return PolicyVerdict(tier=final, requires_approval=False, reason="read-only / notification")
    if tier > policy.auto_execute_max_tier:
        return PolicyVerdict(
            tier=final,
            requires_approval=True,
            reason=f"tier {tier} exceeds autonomy ceiling {policy.auto_execute_max_tier}: "
            + "; ".join(reasons),
        )
    confidence = incident.triage.confidence if incident.triage else 0.0
    if confidence < policy.min_confidence_for_auto:
        return PolicyVerdict(
            tier=final,
            requires_approval=True,
            reason=f"triage confidence {confidence:.2f} below auto threshold {policy.min_confidence_for_auto}",
        )
    if auto_actions_so_far >= policy.max_auto_actions_per_incident:
        return PolicyVerdict(
            tier=final,
            requires_approval=True,
            reason=f"automation budget of {policy.max_auto_actions_per_incident} actions exhausted",
        )
    return PolicyVerdict(tier=final, requires_approval=False, reason="; ".join(reasons))


def count_auto_actions(incident: "Incident") -> int:
    return sum(
        1
        for a in incident.actions
        if a.status == ActionStatus.EXECUTED and not a.requires_approval
    )
