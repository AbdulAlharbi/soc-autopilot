"""Investigation agent.

Scopes the incident: who and what else is involved, how the attacker got in,
what is at risk. It pivots the way an analyst would — user → hosts → IPs →
asset owners → their sign-ins — using only read-only tools, then asks the
brain to synthesise findings. With Claude as the brain the model can request
additional read-only queries (bounded) before it commits to a conclusion.

Its output includes a `context` dict — the concrete values (malicious IPs,
PIDs, message IDs, affected hosts...) that the response playbooks template on.
"""
from __future__ import annotations

from typing import Any

from ..models import Incident, InvestigationDecision, InvestigationResult, TimelineEntry
from .base import BaseAgent, domain_of, is_private_ip

INVESTIGATE_SYSTEM = """You are scoping a confirmed or suspected security incident.
Produce concrete findings (each one sentence, evidence-backed), the most likely root cause, whether the attacker moved laterally, and what data is at risk.
If a specific read-only query would materially change your conclusion, list it in follow_up_queries (max 3); otherwise leave it empty.
Only use tools from the provided catalogue."""

MAX_FOLLOWUP_ROUNDS = 2
MAX_FOLLOWUPS_PER_ROUND = 3


class InvestigatorAgent(BaseAgent):
    name = "investigator"

    def run(self, inc: Incident) -> InvestigationResult:
        alert, triage = inc.alert, inc.triage
        assert triage is not None
        ev: list = []

        # ---- pivot 1: events around the alert entities ----------------- #
        events: list[dict[str, Any]] = []
        for kwargs in ({"user": alert.user}, {"host": alert.host}, {"ip": alert.src_ip}, {"ip": alert.dst_ip}):
            if all(kwargs.values()):
                for e in self.call("siem.search", inc, around=alert.timestamp, window_hours=12, **kwargs):
                    if e not in events:
                        events.append(e)

        hosts: list[str] = [h for h in [alert.host] if h]
        users: list[str] = [u for u in [alert.user] if u]
        for e in events:
            if e.get("host") and e["host"] not in hosts:
                hosts.append(e["host"])
            if e.get("user") and e["user"] not in users and e.get("user") == alert.user:
                pass
        src_host = self.env.host_by_ip(alert.src_ip)
        if src_host and src_host not in hosts:
            hosts.append(src_host)

        # ---- pivot 2: hosts → EDR, owners → their sign-ins -------------- #
        edr_hosts: dict[str, Any] = {}
        suspicious: dict[str, list] = {}
        for h in list(hosts):
            rec = self.call("edr.get_host", inc, host=h)
            if rec:
                edr_hosts[h] = {k: rec[k] for k in ("logged_on_user", "isolated", "network") if k in rec}
                sp = self.env.edr.suspicious_processes(h)
                if sp:
                    suspicious[h] = sp
            for e in self.call("siem.search", inc, host=h, around=alert.timestamp, window_hours=12):
                if e not in events:
                    events.append(e)
            owner = self.env.asset(h).get("owner")
            if owner and owner in self.env.iam.users and owner not in users:
                for a in self.call("siem.auth_history", inc, user=owner):
                    if a not in events:
                        events.append(a)
                    if a.get("src_ip") and not is_private_ip(a["src_ip"]) and self.env.ti.lookup(a["src_ip"]).get("verdict") == "malicious":
                        if owner not in users:
                            users.append(owner)
        ev.append(self.evidence("siem", f"{len(events)} events across {len(hosts)} host(s)", events))
        ev.append(self.evidence("edr", f"{len(suspicious)} host(s) with suspicious processes", suspicious))

        # ---- IOCs and threat intel ------------------------------------ #
        iocs: dict[str, list[str]] = {"ip": [], "domain": [], "hash": []}
        for e in events:
            for k in ("src_ip", "dst_ip"):
                if e.get(k) and not is_private_ip(e[k]) and e[k] not in iocs["ip"]:
                    iocs["ip"].append(e[k])
            for k in ("dst_domain", "url", "sender"):
                d = domain_of(e[k]) if e.get(k) else None
                if d and d not in iocs["domain"]:
                    iocs["domain"].append(d)
        for h, procs in suspicious.items():
            for p in procs:
                if p.get("sha256") and p["sha256"] not in iocs["hash"]:
                    iocs["hash"].append(p["sha256"])
            for n in (edr_hosts.get(h, {}).get("network") or []):
                if any(n.get("pid") == p.get("pid") for p in procs) and not is_private_ip(n.get("remote_ip")):
                    if n["remote_ip"] not in iocs["ip"]:
                        iocs["ip"].append(n["remote_ip"])
        ti = {i: self.call("threat_intel.lookup", inc, ioc=i) for kind in iocs.values() for i in kind}
        ev.append(self.evidence("threat_intel", f"{sum(1 for v in ti.values() if v.get('verdict') == 'malicious')} malicious of {len(ti)}", ti))

        malicious_ips = [i for i in iocs["ip"] if ti[i].get("verdict") == "malicious"]
        # IPs that a suspicious process is talking to are blocked even if TI has never seen them
        for h, procs in suspicious.items():
            for n in (edr_hosts.get(h, {}).get("network") or []):
                if any(n.get("pid") == p.get("pid") for p in procs) and not is_private_ip(n.get("remote_ip")) and n["remote_ip"] not in malicious_ips:
                    malicious_ips.append(n["remote_ip"])

        # compromised users: anyone in scope who authenticated from attacker infrastructure
        compromised_users = []
        for e in events:
            if e.get("event_type") in ("auth_success", "vpn_login") and e.get("src_ip") in malicious_ips and e.get("user"):
                if e["user"] not in compromised_users:
                    compromised_users.append(e["user"])

        # ---- identity persistence and campaign scope ------------------ #
        profile = self.call("iam.get_user", inc, user=alert.user) if alert.user else {}
        user_changes = profile.get("recent_changes", []) if profile else []
        oauth_app_ids = [c.get("ref") for c in user_changes if c.get("type") == "oauth_consent" and c.get("ref")]

        campaign: list[dict[str, Any]] = []
        for e in events:
            if e.get("event_type") == "email_delivered" and e.get("user") == alert.user and e.get("sender"):
                sender_dom = domain_of(e["sender"])
                linked = ti.get(sender_dom, {}).get("verdict") in ("malicious", "suspicious") or (
                    ti.get(domain_of(e.get("url", "")) or "", {}).get("verdict") == "malicious" if e.get("url") else False
                )
                attach = e.get("attachment")
                if attach and not linked:
                    linked = any(attach.lower() in (p.get("cmdline") or "").lower()
                                 for h in hosts for p in (self.env.edr.hosts.get(h, {}).get("processes", [])))
                if linked:
                    for m in self.call("email_gateway.find_messages", inc, sender=e["sender"]):
                        if m["status"] == "delivered" and m not in campaign:
                            campaign.append(m)
        if campaign:
            ev.append(self.evidence("email_gateway", f"campaign reached {len(campaign)} mailbox(es)", campaign))

        malicious_pids = [p["pid"] for p in suspicious.get(alert.host, [])] if alert.host else []

        # ---- timeline ------------------------------------------------- #
        timeline = sorted(
            (TimelineEntry(timestamp=e["ts"], source=e.get("source", "siem"),
                           description=f"[{e.get('event_type')}] {e.get('user') or ''}@{e.get('host') or e.get('src_ip') or ''}: {e.get('details') or e.get('subject') or ''}".strip())
             for e in events),
            key=lambda t: t.timestamp,
        )[:40]

        # ---- brain synthesis (with optional bounded follow-ups) -------- #
        context: dict[str, Any] = {
            "alert": alert.model_dump(mode="json"),
            "triage": triage.model_dump(mode="json", exclude={"evidence"}),
            "signals": triage.signals,
            "asset": self.env.asset(alert.host),
            "affected_hosts": hosts,
            "affected_users": users,
            "compromised_users": compromised_users,
            "iocs": iocs,
            "malicious_ips": malicious_ips,
            "evidence": {
                "siem_events": events[:40],
                "edr_hosts": edr_hosts,
                "suspicious_processes": suspicious,
                "ti": ti,
                "user_changes": user_changes,
                "campaign_messages": campaign,
            },
            "read_only_tools": self.tools.catalogue(read_only=True),
        }
        decision = self.brain.decide("investigate", context, InvestigationDecision, system=INVESTIGATE_SYSTEM)
        rounds = 0
        while decision.follow_up_queries and rounds < MAX_FOLLOWUP_ROUNDS:
            rounds += 1
            extra = []
            for q in decision.follow_up_queries[:MAX_FOLLOWUPS_PER_ROUND]:
                name = f"{q.tool}.{q.operation}"
                if not self.tools.has(name) or not self.tools.spec(name).read_only:
                    self.log(inc, "followup_rejected", tool=name, reason="unknown or not read-only")
                    continue
                try:
                    extra.append({"query": q.model_dump(), "result": self.call(name, inc, **q.params)})
                except Exception as exc:  # noqa: BLE001
                    extra.append({"query": q.model_dump(), "error": str(exc)})
            context.setdefault("follow_up_results", []).extend(extra)
            ev.append(self.evidence("follow_up", f"round {rounds}: {len(extra)} query(ies)", extra))
            decision = self.brain.decide("investigate", context, InvestigationDecision, system=INVESTIGATE_SYSTEM)

        for kind, vals in decision.additional_iocs.items():
            iocs.setdefault(kind, []).extend(v for v in vals if v not in iocs.get(kind, []))
        self.log(inc, "investigation_decided", brain=self.brain.name, rounds=rounds, **decision.model_dump(mode="json", exclude={"follow_up_queries"}))

        playbook_ctx = {
            "user": alert.user, "host": alert.host, "src_ip": alert.src_ip, "alert_rule": alert.rule,
            "affected_hosts": hosts, "affected_users": users, "compromised_users": [u for u in compromised_users if u != alert.user],
            "malicious_ips": malicious_ips, "malicious_pids": malicious_pids,
            "campaign_message_ids": [m["message_id"] for m in campaign],
            "oauth_app_ids": oauth_app_ids,
            "signals": triage.signals,
        }
        return InvestigationResult(
            affected_hosts=hosts, affected_users=users, iocs=iocs, timeline=timeline,
            findings=decision.findings, root_cause=decision.root_cause, lateral_movement=decision.lateral_movement,
            data_at_risk=decision.data_at_risk, confidence=decision.confidence, rationale=decision.rationale,
            evidence=ev, context=playbook_ctx, decided_by=self.brain.name,
        )
