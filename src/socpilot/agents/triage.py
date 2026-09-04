"""Triage agent.

Answers three questions fast: is this real, how bad is it, and which playbook
applies. It does a fixed, cheap enrichment pass (asset, identity, threat
intel, allowlists, EDR, recent SIEM activity), distils that into named
*signals*, and asks the brain for a decision over those signals plus the raw
evidence. The signals are what make the decision explainable — and what the
heuristic brain reasons over.
"""
from __future__ import annotations

from typing import Any

from ..models import Incident, TriageDecision, TriageResult
from .base import BaseAgent, domain_of, is_private_ip

TRIAGE_SYSTEM = """You are performing alert triage. Decide verdict, severity, confidence and category.
Categories you may return: credential_compromise, malware_c2, ransomware, recon_false_positive, generic_suspicious.
false_positive means the detection logic misfired on authorised activity. benign means real but authorised.
Be sceptical of single signals; be decisive when multiple independent signals corroborate."""


class TriageAgent(BaseAgent):
    name = "triage"

    def run(self, inc: Incident) -> TriageResult:
        alert = inc.alert
        ev: list = []

        asset = self.call("assets.get", inc, host=alert.host) if alert.host else {}
        profile = self.call("iam.get_user", inc, user=alert.user) if alert.user else {}
        ev.append(self.evidence("assets", f"{alert.host}: {asset.get('type')}, criticality={asset.get('criticality')}, env={asset.get('environment')}", asset))
        ev.append(self.evidence("iam", f"{alert.user}: {profile.get('title')}, privileged={profile.get('privileged')}, type={profile.get('account_type')}", profile))

        # Threat intel on everything the alert names
        iocs = self._alert_iocs(alert.model_dump())
        ti = {ioc: self.call("threat_intel.lookup", inc, ioc=ioc) for ioc in iocs}
        ti_malicious = [dict(ioc=k, tags=v.get("tags", []), score=v.get("score")) for k, v in ti.items() if v.get("verdict") == "malicious"]
        ti_suspicious = [dict(ioc=k, tags=v.get("tags", [])) for k, v in ti.items() if v.get("verdict") == "suspicious"]
        ev.append(self.evidence("threat_intel", f"{len(ti_malicious)} malicious, {len(ti_suspicious)} suspicious of {len(ti)} indicators", ti))

        allow = self.env.allowlists.match_scanner(alert.src_ip, alert.timestamp)
        if allow:
            ev.append(self.evidence("allowlist", f"{alert.src_ip} matches '{allow['name']}' ({allow['change_ref']}), in_window={allow['in_window']}", allow))

        edr_host = self.call("edr.get_host", inc, host=alert.host) if alert.host else None
        suspicious = self.env.edr.suspicious_processes(alert.host) if alert.host else []
        if edr_host:
            ev.append(self.evidence("edr", f"{alert.host}: {len(edr_host.get('processes', []))} processes, {len(suspicious)} suspicious, isolated={edr_host.get('isolated')}", {"suspicious": suspicious, "network": edr_host.get("network")}))

        recent = self.call("siem.search", inc, user=alert.user, around=alert.timestamp, window_hours=6) if alert.user else []
        if alert.host:
            recent += [e for e in self.call("siem.search", inc, host=alert.host, around=alert.timestamp, window_hours=6) if e not in recent]
        ev.append(self.evidence("siem", f"{len(recent)} related events in ±6h", recent))

        signals = self._signals(alert.model_dump(), asset, profile, ti_malicious, ti_suspicious, allow, suspicious, recent)
        self.log(inc, "signals_computed", signals=signals)

        context = {
            "alert": alert.model_dump(mode="json"),
            "signals": signals,
            "asset": asset,
            "user_profile": {k: v for k, v in profile.items() if k != "recent_changes"},
            "identity_recent_changes": profile.get("recent_changes", []),
            "threat_intel": ti,
            "allowlist_match": allow,
            "suspicious_processes": suspicious,
            "edr_network": (edr_host or {}).get("network", []),
            "recent_siem_events": recent[:25],
        }
        decision = self.brain.decide("triage", context, TriageDecision, system=TRIAGE_SYSTEM)
        self.log(inc, "triage_decided", brain=self.brain.name, **decision.model_dump(mode="json"))

        return TriageResult(**decision.model_dump(), signals=signals, evidence=ev, decided_by=self.brain.name)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _alert_iocs(alert: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for key in ("src_ip", "dst_ip"):
            if alert.get(key) and not is_private_ip(alert[key]):
                out.append(alert[key])
        for k, v in (alert.get("indicators") or {}).items():
            if not isinstance(v, str):
                continue
            if k.endswith("_ip") and not is_private_ip(v):
                out.append(v)
            elif k in ("domain", "url", "sender", "hash", "sha256") or "domain" in k or "url" in k:
                d = domain_of(v) if k != "hash" and k != "sha256" else v
                if d:
                    out.append(d)
        return list(dict.fromkeys(out))

    def _signals(self, alert, asset, profile, ti_mal, ti_sus, allow, suspicious, recent) -> dict[str, Any]:
        tags = set(alert.get("tags", []))
        details = " ".join((e.get("details") or "") + " " + (e.get("event_type") or "") for e in recent).lower()
        changes = profile.get("recent_changes", []) or []
        s: dict[str, Any] = {
            "allowlisted_source": bool(allow),
            "allowlist_in_window": allow.get("in_window") if allow else None,
            "allowlist_name": allow.get("name") if allow else None,
            "allowlist_change_ref": allow.get("change_ref") if allow else None,
            "ti_malicious": ti_mal,
            "ti_suspicious": ti_sus,
            "suspicious_process_count": len(suspicious),
            "impossible_travel": "impossible_travel" in tags,
            "beaconing": "beaconing" in tags or "c2" in tags,
            "shadow_copy_deletion": "shadow_copy_deletion" in tags or "vssadmin" in details,
            "backup_tampering": any(k in details for k in ("wbadmin", "bcdedit", "recoveryenabled")),
            "exfil_staging": "rclone" in details or "mega:" in details,
            "mailbox_rule_created": any(c.get("type") == "mailbox_rule_created" for c in changes) or "mailbox_rule_created" in details,
            "oauth_consent": any(c.get("type") == "oauth_consent" for c in changes),
            "credential_access_attempted": any(k in details for k in ("whoami", "net.exe group", "mimikatz", "lsass")),
            "service_account_interactive_logon": profile.get("account_type") == "service"
            and any(e.get("event_type") == "logon" and ("type 2" in (e.get("details") or "").lower() or "type 10" in (e.get("details") or "").lower()) for e in recent),
            "off_hours": self.is_off_hours(alert["timestamp"]) if hasattr(alert["timestamp"], "hour") else False,
            "asset_criticality": asset.get("criticality"),
            "asset_environment": asset.get("environment"),
            "user_privileged": bool(profile.get("privileged")),
            "user_service_account": profile.get("account_type") == "service",
            "user_vip": bool(profile.get("vip")),
        }
        return s
