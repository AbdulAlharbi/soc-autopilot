"""Domain models shared by every agent in the system.

Everything an agent produces is a typed, validated object. That is what makes
the workflow auditable: an LLM never mutates state directly, it only proposes
structured decisions that the orchestrator validates against policy.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    SUSPICIOUS = "suspicious"          # needs investigation before a call is made
    BENIGN = "benign"                  # real activity, authorised (e.g. red team)
    FALSE_POSITIVE = "false_positive"  # detection logic misfired


class IncidentState(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    PLANNING = "planning"
    CONTAINING = "containing"
    AWAITING_APPROVAL = "awaiting_approval"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED_FALSE_POSITIVE = "closed_false_positive"
    CLOSED_BENIGN = "closed_benign"
    ESCALATED = "escalated"

    @property
    def terminal(self) -> bool:
        return self in {
            IncidentState.RESOLVED,
            IncidentState.CLOSED_FALSE_POSITIVE,
            IncidentState.CLOSED_BENIGN,
            IncidentState.ESCALATED,
        }


class RiskTier(int, Enum):
    """How much damage an action can do if the agent is wrong."""

    READ_ONLY = 0   # queries, lookups, notifications
    LOW = 1         # reversible, narrow blast radius (block one IP, quarantine one email)
    MEDIUM = 2      # disruptive to one user/host (isolate workstation, reset password)
    HIGH = 3        # disruptive to the business (isolate prod server, disable service account)


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    FAILED = "failed"
    SKIPPED = "skipped"


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #
class Alert(BaseModel):
    id: str
    source: str                       # e.g. "siem", "edr", "ids", "email_gateway"
    rule: str
    title: str
    description: str = ""
    timestamp: datetime
    severity_hint: Severity = Severity.MEDIUM
    host: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    indicators: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Evidence and agent outputs
# --------------------------------------------------------------------------- #
class Evidence(BaseModel):
    source: str
    summary: str
    data: Any = None
    collected_at: datetime = Field(default_factory=utcnow)


class TriageResult(BaseModel):
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    category: str                     # maps to a playbook: credential_compromise, malware_c2, ...
    rationale: str
    mitre_techniques: list[str] = Field(default_factory=list)
    signals: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    decided_by: str = ""


class TimelineEntry(BaseModel):
    timestamp: datetime
    source: str
    description: str


class InvestigationResult(BaseModel):
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    iocs: dict[str, list[str]] = Field(default_factory=dict)   # {"ip": [...], "domain": [...], "hash": [...]}
    timeline: list[TimelineEntry] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    root_cause: str = ""
    lateral_movement: bool = False
    data_at_risk: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)      # values playbooks can template on
    decided_by: str = ""


class Approval(BaseModel):
    requested_at: datetime = Field(default_factory=utcnow)
    decided_at: Optional[datetime] = None
    approver: Optional[str] = None
    approved: Optional[bool] = None
    comment: str = ""


class ProposedAction(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ACT"))
    tool: str
    operation: str
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    reversible: bool = True
    risk_tier: RiskTier = RiskTier.LOW
    requires_approval: bool = False
    policy_reason: str = ""
    status: ActionStatus = ActionStatus.PROPOSED
    result: Optional[dict[str, Any]] = None
    approval: Optional[Approval] = None
    verified: Optional[bool] = None

    @property
    def key(self) -> str:
        return f"{self.tool}.{self.operation}"

    def describe(self) -> str:
        args = ", ".join(f"{k}={v}" for k, v in self.params.items())
        return f"{self.key}({args})"


class Communication(BaseModel):
    channel: str                      # chat, email, ticket
    recipient: str
    subject: str
    body: str
    sent_at: datetime = Field(default_factory=utcnow)
    ref: Optional[str] = None


class Transition(BaseModel):
    at: datetime = Field(default_factory=utcnow)
    from_state: IncidentState
    to_state: IncidentState
    actor: str
    note: str = ""


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: new_id("INC"))
    alert: Alert
    state: IncidentState = IncidentState.NEW
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    triage: Optional[TriageResult] = None
    investigation: Optional[InvestigationResult] = None
    actions: list[ProposedAction] = Field(default_factory=list)
    communications: list[Communication] = Field(default_factory=list)
    ticket_id: Optional[str] = None
    report_path: Optional[str] = None
    notes: list[str] = Field(default_factory=list)
    history: list[Transition] = Field(default_factory=list)
    brain: str = ""

    def transition(self, to_state: IncidentState, actor: str, note: str = "") -> None:
        self.history.append(
            Transition(from_state=self.state, to_state=to_state, actor=actor, note=note)
        )
        self.state = to_state
        self.updated_at = utcnow()

    def note(self, text: str) -> None:
        self.notes.append(text)

    @property
    def pending_actions(self) -> list[ProposedAction]:
        return [a for a in self.actions if a.status == ActionStatus.AWAITING_APPROVAL]

    @property
    def executed_actions(self) -> list[ProposedAction]:
        return [a for a in self.actions if a.status == ActionStatus.EXECUTED]

    def get_action(self, action_id: str) -> ProposedAction:
        for a in self.actions:
            if a.id == action_id:
                return a
        raise KeyError(f"No action {action_id} on incident {self.id}")


# --------------------------------------------------------------------------- #
# LLM decision schemas (what the model is asked to return)
# --------------------------------------------------------------------------- #
class TriageDecision(BaseModel):
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    category: str
    rationale: str
    mitre_techniques: list[str] = Field(default_factory=list)


class ToolRequest(BaseModel):
    tool: str
    operation: str
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class InvestigationDecision(BaseModel):
    findings: list[str]
    root_cause: str
    lateral_movement: bool
    data_at_risk: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    additional_iocs: dict[str, list[str]] = Field(default_factory=dict)
    follow_up_queries: list[ToolRequest] = Field(
        default_factory=list,
        description="Read-only tool calls the investigator wants run before concluding",
    )


class ActionSpec(BaseModel):
    tool: str
    operation: str
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""


class ResponseDecision(BaseModel):
    drop: dict[str, str] = Field(
        default_factory=dict, description="action_id -> reason for removing it from the plan"
    )
    add: list[ActionSpec] = Field(default_factory=list)
    rationale: str = ""
