"""Rule-based brain.

Encodes the judgement of a competent tier-2 analyst as explicit rules over the
*signals* the agents compute. It is intentionally simple and transparent: this
is the floor the LLM has to beat, the fallback if the LLM is unavailable, and
the reason the demo and test-suite run without an API key.
"""
from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

from ..models import (
    InvestigationDecision,
    ResponseDecision,
    Severity,
    TriageDecision,
    Verdict,
)

T = TypeVar("T", bound=BaseModel)

MITRE_BY_CATEGORY = {
    "credential_compromise": ["T1566.002", "T1550.004", "T1078.004", "T1114.003", "T1098.003"],
    "malware_c2": ["T1566.001", "T1204.002", "T1071.001", "T1087"],
    "ransomware": ["T1078.002", "T1021.001", "T1490", "T1567.002"],
    "recon_false_positive": ["T1046"],
    "generic_suspicious": [],
}


class HeuristicBrain:
    name = "heuristic"

    # ------------------------------------------------------------------ #
    def decide(self, task: str, context: dict[str, Any], schema: type[T], system: str = "") -> T:
        handler = {
            "triage": self._triage,
            "investigate": self._investigate,
            "plan_response": self._plan_response,
        }.get(task)
        if handler is None:
            raise ValueError(f"HeuristicBrain has no rules for task {task!r}")
        result = handler(context)
        if not isinstance(result, schema):
            result = schema.model_validate(result.model_dump())
        return result

    # ------------------------------------------------------------------ #
    def _triage(self, ctx: dict[str, Any]) -> TriageDecision:
        s = ctx.get("signals", {})
        tags = set(ctx.get("alert", {}).get("tags", []))
        reasons: list[str] = []

        # Rule 0: allowlisted scanner / red team inside its window -> false positive
        if s.get("allowlisted_source") and ({"port_scan", "recon", "scan"} & tags):
            if s.get("allowlist_in_window", True):
                return TriageDecision(
                    verdict=Verdict.FALSE_POSITIVE, severity=Severity.LOW, confidence=0.93,
                    category="recon_false_positive",
                    rationale=f"Source {ctx['alert'].get('src_ip')} is the allowlisted scanner "
                              f"'{s.get('allowlist_name')}' ({s.get('allowlist_change_ref')}) and the alert "
                              f"fired inside its approved schedule. No malicious TI, no suspicious processes.",
                    mitre_techniques=MITRE_BY_CATEGORY["recon_false_positive"],
                )
            reasons.append("allowlisted scanner but OUTSIDE its approved window")

        score = 0.0
        mal = s.get("ti_malicious", [])
        if mal:
            score += min(0.5, 0.3 * len(mal))
            reasons.append(f"{len(mal)} indicator(s) with malicious threat-intel verdict: "
                           + ", ".join(m["ioc"] for m in mal[:3]))
        if s.get("suspicious_process_count", 0):
            score += 0.25
            reasons.append(f"{s['suspicious_process_count']} suspicious process(es) on host per EDR")
        if s.get("impossible_travel"):
            score += 0.2
            reasons.append("impossible-travel sign-in with token replay characteristics")
        if s.get("mailbox_rule_created"):
            score += 0.2
            reasons.append("attacker-style inbox forwarding rule created from the anomalous IP")
        if s.get("oauth_consent"):
            score += 0.1
            reasons.append("OAuth consent granted to an unverified app from the anomalous IP")
        if s.get("beaconing"):
            score += 0.2
            reasons.append("periodic outbound connections with low jitter (beaconing)")
        if s.get("shadow_copy_deletion") or s.get("backup_tampering"):
            score += 0.35
            reasons.append("shadow copy / backup catalog deletion — classic ransomware precursor")
        if s.get("exfil_staging"):
            score += 0.15
            reasons.append("bulk copy tooling (rclone) staging data to cloud storage")
        if s.get("service_account_interactive_logon"):
            score += 0.15
            reasons.append("service account used for interactive/RDP logon, which policy forbids")
        if s.get("credential_access_attempted"):
            score += 0.1
            reasons.append("post-exploitation discovery commands (whoami, net group)")
        if s.get("off_hours"):
            score += 0.05
            reasons.append("activity outside business hours")

        if s.get("shadow_copy_deletion") or s.get("backup_tampering"):
            category, severity = "ransomware", Severity.CRITICAL
        elif s.get("beaconing") or s.get("suspicious_process_count", 0) and mal:
            category = "malware_c2"
            severity = Severity.CRITICAL if s.get("asset_criticality") == "critical" else Severity.HIGH
        elif s.get("impossible_travel") or s.get("mailbox_rule_created") or "phishing" in tags:
            category = "credential_compromise"
            severity = Severity.CRITICAL if s.get("user_privileged") else Severity.HIGH
        else:
            category, severity = "generic_suspicious", Severity.MEDIUM

        confidence = round(min(0.97, 0.45 + score), 2)
        if score >= 0.5:
            verdict = Verdict.TRUE_POSITIVE
        elif score >= 0.2:
            verdict, severity = Verdict.SUSPICIOUS, Severity.MEDIUM
        else:
            verdict, severity, confidence = Verdict.BENIGN, Severity.LOW, 0.6
            reasons.append("no corroborating signals beyond the alert itself")

        return TriageDecision(
            verdict=verdict, severity=severity, confidence=confidence, category=category,
            rationale="; ".join(reasons) + f". Composite evidence score {score:.2f}.",
            mitre_techniques=MITRE_BY_CATEGORY[category],
        )

    # ------------------------------------------------------------------ #
    def _investigate(self, ctx: dict[str, Any]) -> InvestigationDecision:
        s = ctx.get("signals", {})
        ev = ctx.get("evidence", {})
        alert = ctx.get("alert", {})
        findings: list[str] = []

        for ioc, rec in ev.get("ti", {}).items():
            if rec.get("verdict") == "malicious":
                fam = f", {rec['malware_family']}" if rec.get("malware_family") else ""
                findings.append(f"{ioc} is known-bad ({', '.join(rec.get('tags', []))}{fam}).")
        for h, procs in ev.get("suspicious_processes", {}).items():
            for p in procs:
                findings.append(f"{h}: {p.get('name')} (pid {p.get('pid')}) at {p.get('path')} — "
                                f"{'unsigned, ' if not p.get('signed') else ''}cmd: {p.get('cmdline', '')}".rstrip(", :"))
        for c in ev.get("user_changes", []):
            findings.append(f"Identity change on {alert.get('user')}: {c.get('type')} — {c.get('details')}")
        campaign = ev.get("campaign_messages", [])
        if campaign:
            others = sorted({m['recipient'] for m in campaign} - {alert.get('user')})
            findings.append(f"Same phishing campaign delivered to {len(campaign)} mailbox(es)"
                            + (f"; other recipients: {', '.join(others)}" if others else "") + ".")
        if s.get("service_account_interactive_logon"):
            findings.append("Service account performed interactive/RDP logons across hosts — not backup-job behaviour.")
        if s.get("exfil_staging"):
            findings.append("rclone is copying ERP export data to external cloud storage — exfiltration in progress.")

        hosts = ctx.get("affected_hosts", [])
        users = ctx.get("affected_users", [])
        lateral = len(hosts) > 1 or s.get("service_account_interactive_logon", False)

        if s.get("shadow_copy_deletion"):
            root = ("Admin VPN session accepted after repeated MFA push prompts (MFA fatigue) from a ransomware-affiliate IP; "
                    "attacker then pivoted to the backup service account and RDP'd into production servers.")
            data = ctx.get("asset", {}).get("business_service", "production data") + " — restricted data, backups being destroyed"
        elif s.get("beaconing"):
            root = "User opened a macro-enabled attachment that dropped an unsigned loader; loader established C2."
            data = "Local workstation data and any credentials cached on the host; attacker ran domain discovery."
        elif s.get("impossible_travel"):
            root = ("User submitted credentials to an adversary-in-the-middle phishing page; attacker replayed the "
                    "session token, consented an OAuth mail app, and created a forwarding rule.")
            data = "Mailbox contents including vendor payment schedules (BEC risk)."
        else:
            root = "Undetermined from available telemetry."
            data = "Unknown."

        confidence = 0.9 if len(findings) >= 3 else 0.7 if findings else 0.4
        return InvestigationDecision(
            findings=findings, root_cause=root, lateral_movement=lateral, data_at_risk=data,
            confidence=confidence,
            rationale=f"{len(findings)} corroborating findings across {len(ev.get('siem_events', []))} SIEM events, "
                      f"{len(ev.get('edr_hosts', {}))} EDR host(s), {len(ev.get('ti', {}))} TI lookups. "
                      f"Affected hosts: {', '.join(hosts) or 'none'}; users: {', '.join(users) or 'none'}.",
            additional_iocs={}, follow_up_queries=[],
        )

    # ------------------------------------------------------------------ #
    def _plan_response(self, ctx: dict[str, Any]) -> ResponseDecision:
        return ResponseDecision(drop={}, add=[], rationale="Playbook plan accepted as-is; policy tiering applied.")

    # ------------------------------------------------------------------ #
    def narrate(self, task: str, context: dict[str, Any], system: str = "") -> str:
        if task == "executive_summary":
            inc = context
            t, inv = inc.get("triage") or {}, inc.get("investigation") or {}
            executed = [a for a in inc.get("actions", []) if a.get("status") == "executed"]
            pending = [a for a in inc.get("actions", []) if a.get("status") in ("awaiting_approval", "denied")]
            lines = [
                f"{inc.get('alert', {}).get('title')} was triaged as {t.get('verdict')} "
                f"({t.get('severity')}, confidence {t.get('confidence')}) and categorised as {t.get('category')}.",
            ]
            if inv.get("root_cause"):
                lines.append(f"Root cause: {inv['root_cause']}")
            if inv.get("data_at_risk"):
                lines.append(f"Data at risk: {inv['data_at_risk']}")
            if executed:
                lines.append(f"{len(executed)} containment action(s) were executed"
                             + (" autonomously" if not any(a.get("requires_approval") for a in executed) else
                                " (some with human approval") + ".")
            if pending:
                lines.append(f"{len(pending)} high-impact action(s) were referred to a human and "
                             f"{'denied' if any(a.get('status') == 'denied' for a in pending) else 'are still pending'}.")
            lines.append(f"Final state: {inc.get('state')}.")
            return " ".join(lines)
        if task == "user_notification":
            return (f"Hi {context.get('display_name', context.get('user'))},\n\n"
                    f"Our security systems detected suspicious activity involving your account or device "
                    f"({context.get('what')}). To protect you and the company we have {context.get('actions_taken')}.\n\n"
                    f"What you need to do: {context.get('next_steps')}\n\n"
                    f"Reference: {context.get('incident_id')}. Reply to this message or contact the SOC if anything looks wrong.")
        if task == "approval_request":
            a = context.get("action", {})
            return (f"*Approval needed — {context.get('incident_id')} ({context.get('severity', '').upper()})*\n"
                    f"Proposed: `{a.get('describe')}`\n"
                    f"Why: {a.get('rationale')}\n"
                    f"Risk tier {a.get('risk_tier')} — {a.get('policy_reason')}\n"
                    f"Business impact: {context.get('impact')}\n"
                    f"Already done autonomously: {context.get('done_so_far')}\n"
                    f"Reply `approve {a.get('id')}` or `deny {a.get('id')} <reason>`.")
        return f"[{task}] " + ", ".join(f"{k}={v}" for k, v in list(context.items())[:6])
