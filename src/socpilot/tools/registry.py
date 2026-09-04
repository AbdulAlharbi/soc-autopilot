"""Tool registry.

Every agent → system interaction goes through `ToolRegistry.call`, which:
  * validates the tool/operation exists,
  * records the call and its result in the audit log,
  * refuses operations that are outside the calling agent's allowed set.

The registry also exposes a catalogue (name, description, parameters, tier)
that is handed to the LLM so it can only propose actions that actually exist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..audit import AuditLog
from .environment import MockEnvironment


@dataclass
class ToolSpec:
    name: str              # "edr.isolate_host"
    description: str
    params: dict[str, str]  # param -> short type/description
    read_only: bool
    fn: Callable[..., Any]
    tags: list[str] = field(default_factory=list)


class ToolError(RuntimeError):
    pass


class ToolRegistry:
    def __init__(self, env: MockEnvironment, audit: AuditLog):
        self.env = env
        self.audit = audit
        self._tools: dict[str, ToolSpec] = {}
        self._register_all()

    # ------------------------------------------------------------------ #
    def _add(self, name: str, description: str, params: dict[str, str], read_only: bool, fn: Callable[..., Any]) -> None:
        self._tools[name] = ToolSpec(name, description, params, read_only, fn)

    def _register_all(self) -> None:
        env = self.env
        # --- read-only -------------------------------------------------- #
        self._add("siem.search", "Search SIEM events by user/host/ip/domain/event_type.",
                  {"user": "str?", "host": "str?", "ip": "str?", "domain": "str?", "event_type": "str?"}, True, env.siem.search)
        self._add("siem.auth_history", "Authentication events for a user.", {"user": "str"}, True, env.siem.auth_history)
        self._add("edr.get_host", "EDR view of a host: processes, network, isolation state.", {"host": "str"}, True, env.edr.get_host)
        self._add("threat_intel.lookup", "Reputation for an IP, domain or SHA-256.", {"ioc": "str"}, True, env.ti.lookup)
        self._add("iam.get_user", "Directory profile incl. privilege, VIP, recent changes.", {"user": "str"}, True, env.iam.get_user)
        self._add("assets.get", "Asset inventory record: owner, criticality, environment.", {"host": "str"}, True, env.asset)
        self._add("email_gateway.find_messages", "Find delivered messages by sender/subject/recipient.",
                  {"sender": "str?", "subject": "str?", "recipient": "str?"}, True, env.email.find_messages)
        # --- notifications / tracking (side effects, but harmless) -------- #
        self._add("ticketing.create_ticket", "Open a ticket in a queue.",
                  {"title": "str", "body": "str", "queue": "str", "severity": "str"}, True, env.ticketing.create_ticket)
        self._add("ticketing.update_ticket", "Add a comment / fields to a ticket.", {"ticket_id": "str", "comment": "str"}, True, env.ticketing.update_ticket)
        self._add("ticketing.resolve_ticket", "Resolve a ticket.", {"ticket_id": "str", "resolution": "str"}, True, env.ticketing.resolve_ticket)
        self._add("chat.post", "Post to a chat channel.", {"channel": "str", "text": "str"}, True, env.chat.post)
        self._add("mail.send", "Send an email.", {"to": "str", "subject": "str", "body": "str"}, True, env.mail.send)
        # --- containment ------------------------------------------------ #
        self._add("firewall.block_ip", "Block an external IP at the perimeter.", {"ip": "str"}, False, env.firewall.block_ip)
        self._add("firewall.block_subnet", "Block a CIDR at the perimeter.", {"cidr": "str"}, False, env.firewall.block_subnet)
        self._add("email_gateway.quarantine_message", "Pull a message from a mailbox.", {"message_id": "str"}, False, env.email.quarantine_message)
        self._add("iam.remove_mailbox_rules", "Delete recently created inbox rules.", {"user": "str"}, False, env.iam.remove_mailbox_rules)
        self._add("iam.revoke_oauth_grant", "Revoke a consented OAuth application.", {"user": "str", "app_id": "str"}, False, env.iam.revoke_oauth_grant)
        self._add("iam.revoke_sessions_and_reset_password", "Kill sessions, invalidate tokens, force password reset.", {"user": "str"}, False, env.iam.revoke_sessions_and_reset_password)
        self._add("iam.enforce_mfa_reregistration", "Clear MFA methods and require re-enrolment.", {"user": "str"}, False, env.iam.enforce_mfa_reregistration)
        self._add("iam.disable_user", "Disable an account entirely.", {"user": "str"}, False, env.iam.disable_user)
        self._add("edr.scan_host", "Run an on-demand EDR scan.", {"host": "str"}, False, env.edr.scan_host)
        self._add("edr.collect_forensics", "Collect memory + triage package.", {"host": "str"}, False, env.edr.collect_forensics)
        self._add("edr.kill_process", "Terminate a process by PID.", {"host": "str", "pid": "int"}, False, env.edr.kill_process)
        self._add("edr.isolate_host", "Network-contain a host (EDR channel stays up).", {"host": "str"}, False, env.edr.isolate_host)

    # ------------------------------------------------------------------ #
    def has(self, name: str) -> bool:
        return name in self._tools

    def spec(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise ToolError(f"unknown tool {name}")
        return self._tools[name]

    def catalogue(self, read_only: Optional[bool] = None) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "params": t.params, "read_only": t.read_only}
            for t in self._tools.values()
            if read_only is None or t.read_only == read_only
        ]

    def call(self, name: str, actor: str, incident_id: str, allow_write: bool = False, **kwargs: Any) -> Any:
        spec = self.spec(name)
        if not spec.read_only and not allow_write:
            raise ToolError(f"{actor} attempted write operation {name} without write authority")
        try:
            result = spec.fn(**kwargs)
            self.audit.record(incident_id, actor, "tool_call", tool=name, params=kwargs,
                              result=_truncate(result))
            return result
        except Exception as exc:  # noqa: BLE001
            self.audit.record(incident_id, actor, "tool_error", tool=name, params=kwargs, error=str(exc))
            raise


def _truncate(value: Any, limit: int = 600) -> Any:
    text = str(value)
    return value if len(text) <= limit else text[:limit] + "...<truncated>"
