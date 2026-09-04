"""Communicator agent.

Owns every interaction with people: the tracking ticket, the SOC channel,
approval requests, and notifications to the affected user, their manager,
the asset owner and the IR lead. Messages are drafted by the brain from a
structured context so they are specific, not boilerplate.
"""
from __future__ import annotations

from typing import Any

from ..models import Communication, Incident, ProposedAction
from .base import BaseAgent


class CommunicatorAgent(BaseAgent):
    name = "communicator"

    # ------------------------------------------------------------------ #
    def open_ticket(self, inc: Incident) -> None:
        t = inc.triage
        assert t is not None
        body = (f"Alert {inc.alert.id} ({inc.alert.rule}): {inc.alert.title}\n\n"
                f"Triage: {t.verdict.value} / {t.severity.value} / confidence {t.confidence}\n"
                f"Category: {t.category}\nMITRE: {', '.join(t.mitre_techniques) or '-'}\n\nRationale: {t.rationale}")
        res = self.call("ticketing.create_ticket", inc, title=f"[{t.severity.value.upper()}] {inc.alert.title}",
                        body=body, queue="soc", severity=t.severity.value)
        inc.ticket_id = res["ticket_id"]
        self._record(inc, "ticket", "soc queue", f"Ticket {inc.ticket_id} opened", body, inc.ticket_id)
        self.post(inc, f":rotating_light: *{inc.id}* opened — {inc.alert.title}\n"
                       f"Triage: *{t.verdict.value}* / *{t.severity.value}* (conf {t.confidence}) → playbook `{t.category}` · ticket {inc.ticket_id}")

    def post(self, inc: Incident, text: str, channel: str | None = None) -> None:
        ch = channel or self.settings.soc_channel
        self.call("chat.post", inc, channel=ch, text=text, thread=inc.id)
        self._record(inc, "chat", ch, inc.id, text)

    def update(self, inc: Incident, text: str) -> None:
        if inc.ticket_id:
            self.call("ticketing.update_ticket", inc, ticket_id=inc.ticket_id, comment=text)
        self.post(inc, text)

    # ------------------------------------------------------------------ #
    def request_approval(self, inc: Incident, act: ProposedAction) -> None:
        done = [a.describe() for a in inc.executed_actions]
        asset = self.env.asset(act.params.get("host"))
        impact = asset.get("business_service") or asset.get("type") or "-"
        if act.params.get("user"):
            u = self.env.iam.get_user(act.params["user"]) or {}
            impact = f"{u.get('title', act.params['user'])} — {impact}" if u else impact
        text = self.brain.narrate("approval_request", {
            "incident_id": inc.id,
            "severity": inc.triage.severity.value if inc.triage else "",
            "action": dict(id=act.id, describe=act.describe(), rationale=act.rationale, risk_tier=act.risk_tier.value, policy_reason=act.policy_reason),
            "impact": impact,
            "done_so_far": "; ".join(done) or "nothing yet",
            "root_cause": inc.investigation.root_cause if inc.investigation else "",
        })
        self.post(inc, text, channel=self.settings.approvals_channel)

    # ------------------------------------------------------------------ #
    def notify_stakeholders(self, inc: Incident, roles: list[dict[str, str]]) -> None:
        alert = inc.alert
        user = self.env.iam.get_user(alert.user) if alert.user else None
        asset = self.env.asset(alert.host)
        executed = inc.executed_actions
        done_text = "; ".join(a.describe() for a in executed) or "no automated changes yet"
        recipients: dict[str, tuple[str, str]] = {}   # email -> (role, display)
        for r in roles:
            role = r.get("role")
            if role == "user" and user and user.get("account_type") == "user":
                recipients[user["email"]] = ("user", user["display_name"])
            elif role == "manager" and user and user.get("manager"):
                m = self.env.iam.get_user(user["manager"])
                if m:
                    recipients[m["email"]] = ("manager", m["display_name"])
            elif role == "asset_owner" and asset.get("owner"):
                o = self.env.iam.get_user(asset["owner"])
                if o:
                    recipients[o["email"]] = ("asset_owner", o["display_name"])
            elif role == "ir_lead":
                recipients[self.settings.ir_lead] = ("ir_lead", "IR Lead")
        for email, (role, display) in recipients.items():
            if role == "user":
                body = self.brain.narrate("user_notification", {
                    "user": alert.user, "display_name": display, "incident_id": inc.id,
                    "what": inc.investigation.root_cause if inc.investigation else alert.title,
                    "actions_taken": done_text,
                    "next_steps": self._next_steps(inc),
                })
                subject = f"[Security] Action required — {inc.id}"
            else:
                body = (f"{display},\n\nThe SOC has {'contained' if inc.executed_actions else 'opened'} incident {inc.id}: {alert.title}.\n"
                        f"Severity: {inc.triage.severity.value if inc.triage else '-'}. "
                        f"{'Root cause: ' + inc.investigation.root_cause if inc.investigation else ''}\n\n"
                        f"Automated actions: {done_text}.\n"
                        + (f"Pending your/leadership decision: {'; '.join(a.describe() for a in inc.pending_actions)}.\n" if inc.pending_actions else "")
                        + f"\nTicket: {inc.ticket_id}. This is an automated notice from SOC Autopilot; a human analyst is on the ticket.")
                subject = f"[Security] {inc.id} — {alert.title} ({role.replace('_', ' ')} notice)"
            self.call("mail.send", inc, to=email, subject=subject, body=body)
            self._record(inc, "email", email, subject, body)

    def _next_steps(self, inc: Incident) -> str:
        cat = inc.triage.category if inc.triage else ""
        if cat == "credential_compromise":
            return ("Set a new password via the self-service portal, re-enrol MFA, and review your inbox rules. "
                    "Do not re-open the 'Overdue invoice' email.")
        if cat == "malware_c2":
            return ("Your device is isolated from the network; IT will contact you for a rebuild. "
                    "Do not use it, and change any passwords you typed on it today.")
        return "No action needed from you right now; the SOC will follow up."

    def close(self, inc: Incident, resolution: str) -> None:
        if inc.ticket_id:
            self.call("ticketing.resolve_ticket", inc, ticket_id=inc.ticket_id, resolution=resolution)
        self.post(inc, f":white_check_mark: *{inc.id}* → {inc.state.value}: {resolution}")

    def _record(self, inc: Incident, channel: str, recipient: str, subject: str, body: str, ref: str | None = None) -> None:
        inc.communications.append(Communication(channel=channel, recipient=recipient, subject=subject, body=body, ref=ref))
