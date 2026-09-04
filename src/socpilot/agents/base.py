"""Common plumbing for all agents."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Any, Optional

from ..audit import AuditLog
from ..config import Settings
from ..llm.base import Brain
from ..models import Evidence, Incident
from ..tools.environment import MockEnvironment
from ..tools.registry import ToolRegistry


class BaseAgent:
    name = "agent"
    can_write = False   # only the Responder may execute state-changing tools

    def __init__(self, brain: Brain, tools: ToolRegistry, env: MockEnvironment, audit: AuditLog, settings: Settings):
        self.brain = brain
        self.tools = tools
        self.env = env
        self.audit = audit
        self.settings = settings

    # ------------------------------------------------------------------ #
    def call(self, tool: str, incident: Incident, **kwargs: Any) -> Any:
        return self.tools.call(tool, actor=self.name, incident_id=incident.id, allow_write=self.can_write, **kwargs)

    def log(self, incident: Incident, event: str, **payload: Any) -> None:
        self.audit.record(incident.id, self.name, event, **payload)

    def evidence(self, source: str, summary: str, data: Any = None) -> Evidence:
        return Evidence(source=source, summary=summary, data=data)

    # ------------------------------------------------------------------ #
    def is_off_hours(self, ts: datetime) -> bool:
        local_hour = (ts + timedelta(hours=self.settings.business_tz_offset_hours)).hour
        start, end = self.settings.business_hours
        return not (start <= local_hour < end)


def is_private_ip(value: Optional[str]) -> bool:
    if not value or "/" in value:
        return True
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return True


def domain_of(url_or_email: str) -> Optional[str]:
    v = url_or_email.strip()
    if "@" in v:
        return v.split("@", 1)[1].lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    host = v.split("/", 1)[0].split(":", 1)[0].lower()
    return host or None
