"""Simulated enterprise systems.

Each class mirrors the surface of a real product (Splunk/Sentinel, CrowdStrike/
Defender, Entra ID, a TI platform, an email gateway, a firewall, Jira/ServiceNow,
Slack). They are stateful: isolating a host or disabling a user changes what
later queries return, so the agents can *verify* their own containment.

Swapping a mock for a real system means implementing the same methods against
the vendor's API — see docs/INTEGRATIONS.md.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from ..models import new_id


def _load(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class SIEM:
    def __init__(self, events: list[dict[str, Any]]):
        self.events = sorted(events, key=lambda e: e["ts"])

    def search(
        self,
        user: Optional[str] = None,
        host: Optional[str] = None,
        ip: Optional[str] = None,
        domain: Optional[str] = None,
        event_type: Optional[str] = None,
        around: Optional[datetime] = None,
        window_hours: int = 24,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        out = []
        for e in self.events:
            if user and e.get("user") != user:
                continue
            if host and e.get("host") != host:
                continue
            if ip and ip not in (e.get("src_ip"), e.get("dst_ip")):
                continue
            if domain and e.get("dst_domain") != domain:
                continue
            if event_type and e.get("event_type") != event_type:
                continue
            if around:
                ts = _parse_ts(e["ts"])
                if abs((ts - around).total_seconds()) > window_hours * 3600:
                    continue
            out.append(e)
        return out[:limit]

    def auth_history(self, user: str, hours: int = 24) -> list[dict[str, Any]]:
        return [
            e
            for e in self.events
            if e.get("user") == user
            and e.get("event_type") in {"auth_success", "auth_failure", "vpn_login", "logon"}
        ]


class EDR:
    def __init__(self, hosts: dict[str, Any]):
        self.hosts = hosts
        self.forensics: dict[str, str] = {}

    def get_host(self, host: str) -> Optional[dict[str, Any]]:
        h = self.hosts.get(host)
        return dict(h, hostname=host) if h else None

    def suspicious_processes(self, host: str) -> list[dict[str, Any]]:
        h = self.hosts.get(host) or {}
        out = []
        for p in h.get("processes", []):
            path = p.get("path", "").lower()
            odd_location = any(s in path for s in ("appdata", "\\temp\\", "/tmp/", "programdata"))
            lolbin = any(n in p.get("cmdline", "").lower() for n in ("vssadmin", "wbadmin", "bcdedit", "rclone", "mimikatz"))
            if (not p.get("signed") and odd_location) or lolbin:
                out.append(p)
        return out

    def isolate_host(self, host: str) -> dict[str, Any]:
        h = self.hosts[host]
        h["isolated"] = True
        return {"host": host, "isolated": True, "status": "network_contained"}

    def unisolate_host(self, host: str) -> dict[str, Any]:
        self.hosts[host]["isolated"] = False
        return {"host": host, "isolated": False}

    def kill_process(self, host: str, pid: int) -> dict[str, Any]:
        h = self.hosts[host]
        before = len(h["processes"])
        h["processes"] = [p for p in h["processes"] if p["pid"] != int(pid)]
        h["network"] = [n for n in h.get("network", []) if n.get("pid") != int(pid)]
        return {"host": host, "pid": int(pid), "killed": before != len(h["processes"])}

    def scan_host(self, host: str) -> dict[str, Any]:
        findings = self.suspicious_processes(host)
        return {"host": host, "scan": "completed", "suspicious_processes": len(findings)}

    def collect_forensics(self, host: str) -> dict[str, Any]:
        pkg = f"forensics/{host}-{new_id('PKG')}.zip"
        self.forensics[host] = pkg
        return {"host": host, "package": pkg, "artifacts": ["memory", "process_tree", "netstat", "prefetch", "event_logs"]}


class IAM:
    def __init__(self, users: dict[str, Any]):
        self.users = users
        self.disabled: set[str] = set()
        self.reset: set[str] = set()
        self.mfa_reset: set[str] = set()

    def get_user(self, user: str) -> Optional[dict[str, Any]]:
        u = self.users.get(user)
        if not u:
            return None
        return dict(u, username=user, disabled=user in self.disabled)

    def revoke_sessions_and_reset_password(self, user: str) -> dict[str, Any]:
        self.reset.add(user)
        return {"user": user, "sessions_revoked": True, "password_reset": True, "refresh_tokens_invalidated": True}

    def enforce_mfa_reregistration(self, user: str) -> dict[str, Any]:
        self.mfa_reset.add(user)
        return {"user": user, "mfa_methods_cleared": True, "reregistration_required": True}

    def remove_mailbox_rules(self, user: str) -> dict[str, Any]:
        u = self.users[user]
        rules = [c for c in u.get("recent_changes", []) if c["type"] == "mailbox_rule_created"]
        u["recent_changes"] = [c for c in u.get("recent_changes", []) if c["type"] != "mailbox_rule_created"]
        return {"user": user, "rules_removed": [r.get("ref") for r in rules]}

    def revoke_oauth_grant(self, user: str, app_id: str) -> dict[str, Any]:
        u = self.users[user]
        u["recent_changes"] = [c for c in u.get("recent_changes", []) if c.get("ref") != app_id]
        return {"user": user, "app_id": app_id, "grant_revoked": True}

    def disable_user(self, user: str) -> dict[str, Any]:
        self.disabled.add(user)
        return {"user": user, "disabled": True}


class ThreatIntel:
    def __init__(self, indicators: dict[str, Any]):
        self.indicators = indicators

    def lookup(self, ioc: str) -> dict[str, Any]:
        rec = self.indicators.get(ioc)
        if rec:
            return dict(rec, ioc=ioc, known=True)
        kind = "hash" if len(ioc) == 64 else ("ip" if ioc.replace(".", "").isdigit() else "domain")
        return {"ioc": ioc, "type": kind, "verdict": "unknown", "score": 0, "tags": [], "known": False}


class EmailGateway:
    def __init__(self, messages: list[dict[str, Any]]):
        self.messages = messages

    def find_messages(
        self, sender: Optional[str] = None, subject: Optional[str] = None, recipient: Optional[str] = None
    ) -> list[dict[str, Any]]:
        out = []
        for m in self.messages:
            if sender and m["sender"] != sender:
                continue
            if subject and subject.lower() not in m["subject"].lower():
                continue
            if recipient and m["recipient"] != recipient:
                continue
            out.append(m)
        return out

    def quarantine_message(self, message_id: str) -> dict[str, Any]:
        for m in self.messages:
            if m["message_id"] == message_id:
                m["status"] = "quarantined"
                return {"message_id": message_id, "recipient": m["recipient"], "quarantined": True}
        return {"message_id": message_id, "quarantined": False, "error": "not found"}


class Firewall:
    def __init__(self) -> None:
        self.blocked: list[str] = []

    def block_ip(self, ip: str, reason: str = "") -> dict[str, Any]:
        if ip not in self.blocked:
            self.blocked.append(ip)
        return {"ip": ip, "blocked": True, "rule": f"DENY-{ip.replace('.', '-')}", "reason": reason}

    def block_subnet(self, cidr: str, reason: str = "") -> dict[str, Any]:
        self.blocked.append(cidr)
        return {"cidr": cidr, "blocked": True}


class Ticketing:
    def __init__(self) -> None:
        self.tickets: dict[str, dict[str, Any]] = {}

    def create_ticket(self, title: str, body: str, queue: str = "soc", severity: str = "medium", **extra: Any) -> dict[str, Any]:
        tid = new_id("TKT")
        self.tickets[tid] = {
            "id": tid, "title": title, "body": body, "queue": queue, "severity": severity,
            "status": "open", "comments": [], **extra,
        }
        return {"ticket_id": tid, "queue": queue, "status": "open"}

    def update_ticket(self, ticket_id: str, comment: str, **fields: Any) -> dict[str, Any]:
        t = self.tickets[ticket_id]
        t["comments"].append({"ts": datetime.now(timezone.utc).isoformat(), "comment": comment})
        t.update(fields)
        return {"ticket_id": ticket_id, "comments": len(t["comments"]), "status": t["status"]}

    def resolve_ticket(self, ticket_id: str, resolution: str) -> dict[str, Any]:
        t = self.tickets[ticket_id]
        t["status"] = "resolved"
        t["resolution"] = resolution
        return {"ticket_id": ticket_id, "status": "resolved"}


class Chat:
    """Slack-like channel store."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def post(self, channel: str, text: str, thread: Optional[str] = None) -> dict[str, Any]:
        mid = new_id("MSG")
        self.messages.append({"id": mid, "channel": channel, "text": text, "thread": thread,
                              "ts": datetime.now(timezone.utc).isoformat()})
        return {"message_id": mid, "channel": channel}

    def transcript(self, channel: Optional[str] = None) -> list[dict[str, Any]]:
        return [m for m in self.messages if channel is None or m["channel"] == channel]


class Mail:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, to: str, subject: str, body: str) -> dict[str, Any]:
        mid = new_id("MAIL")
        self.sent.append({"id": mid, "to": to, "subject": subject, "body": body,
                          "ts": datetime.now(timezone.utc).isoformat()})
        return {"mail_id": mid, "to": to, "delivered": True}


class Allowlists:
    def __init__(self, data: dict[str, Any]):
        self.data = data

    def match_scanner(self, ip: Optional[str], at: Optional[datetime] = None) -> Optional[dict[str, Any]]:
        for entry in self.data.get("scanners", []):
            if entry["ip"] != ip:
                continue
            sched = entry.get("schedule")
            if sched and at:
                day = at.strftime("%a")
                start = datetime.strptime(sched["start_utc"], "%H:%M").time()
                end = datetime.strptime(sched["end_utc"], "%H:%M").time()
                in_window = day in sched["days"] and start <= at.timetz().replace(tzinfo=None) <= end
                return dict(entry, in_window=in_window)
            return dict(entry, in_window=True)
        return None


class MockEnvironment:
    """One object that holds every simulated system and their mutable state."""

    def __init__(self, fixtures_dir: Path):
        self.fixtures_dir = fixtures_dir
        self.assets: dict[str, Any] = _load(fixtures_dir / "assets.json")
        self.siem = SIEM(_load(fixtures_dir / "siem_events.json"))
        self.edr = EDR(_load(fixtures_dir / "edr.json"))
        self.iam = IAM(_load(fixtures_dir / "users.json"))
        self.ti = ThreatIntel(_load(fixtures_dir / "threat_intel.json"))
        self.email = EmailGateway(_load(fixtures_dir / "email.json"))
        self.allowlists = Allowlists(_load(fixtures_dir / "allowlists.json"))
        self.firewall = Firewall()
        self.ticketing = Ticketing()
        self.chat = Chat()
        self.mail = Mail()

    def asset(self, host: Optional[str]) -> dict[str, Any]:
        if not host:
            return {}
        a = self.assets.get(host)
        return dict(a, hostname=host) if a else {}

    def host_by_ip(self, ip: Optional[str]) -> Optional[str]:
        for name, a in self.assets.items():
            if a.get("ip") == ip:
                return name
        return None

    # ---- persistence: the "world" survives between CLI invocations -------- #
    def snapshot(self) -> dict[str, Any]:
        return {
            "edr_hosts": self.edr.hosts, "forensics": self.edr.forensics,
            "users": self.iam.users, "disabled": sorted(self.iam.disabled),
            "reset": sorted(self.iam.reset), "mfa_reset": sorted(self.iam.mfa_reset),
            "email": self.email.messages, "firewall": self.firewall.blocked,
            "tickets": self.ticketing.tickets, "chat": self.chat.messages, "mail": self.mail.sent,
        }

    def restore(self, snap: dict[str, Any]) -> None:
        self.edr.hosts = snap["edr_hosts"]
        self.edr.forensics = snap.get("forensics", {})
        self.iam.users = snap["users"]
        self.iam.disabled, self.iam.reset, self.iam.mfa_reset = set(snap["disabled"]), set(snap["reset"]), set(snap["mfa_reset"])
        self.email.messages = snap["email"]
        self.firewall.blocked = snap["firewall"]
        self.ticketing.tickets = snap["tickets"]
        self.chat.messages = snap["chat"]
        self.mail.sent = snap["mail"]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.snapshot(), indent=1, default=str), encoding="utf-8")

    @classmethod
    def load(cls, fixtures_dir: Path, path: Path) -> "MockEnvironment":
        env = cls(fixtures_dir)
        if path.exists():
            env.restore(json.loads(path.read_text(encoding="utf-8")))
        return env
