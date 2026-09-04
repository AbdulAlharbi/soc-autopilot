# Incident report — INC-8800C5F1

**Alert:** ALR-2026-0904-1137 · AAD-Impossible-Travel · 2026-09-04 05:37 UTC  
**Title:** Impossible travel: j.alrashid signed in from Lagos, NG 34 minutes after Riyadh, SA  
**Final state:** `resolved` · **Ticket:** TKT-7D3C6AA3 · **Reasoning back-end:** heuristic

## Executive summary

Impossible travel: j.alrashid signed in from Lagos, NG 34 minutes after Riyadh, SA was triaged as true_positive (high, confidence 0.97) and categorised as credential_compromise. Root cause: User submitted credentials to an adversary-in-the-middle phishing page; attacker replayed the session token, consented an OAuth mail app, and created a forwarding rule. Data at risk: Mailbox contents including vendor payment schedules (BEC risk). 9 containment action(s) were executed autonomously. Final state: resolved.

## Triage

| Field | Value |
|---|---|
| Verdict | true_positive |
| Severity | high |
| Confidence | 0.97 |
| Category / playbook | credential_compromise |
| MITRE ATT&CK | T1566.002, T1550.004, T1078.004, T1114.003, T1098.003 |

**Rationale:** 1 indicator(s) with malicious threat-intel verdict: 197.210.53.14; impossible-travel sign-in with token replay characteristics; attacker-style inbox forwarding rule created from the anomalous IP; OAuth consent granted to an unverified app from the anomalous IP. Composite evidence score 0.80.

**Signals:** `impossible_travel`, `mailbox_rule_created`, `oauth_consent`

## Investigation

**Root cause:** User submitted credentials to an adversary-in-the-middle phishing page; attacker replayed the session token, consented an OAuth mail app, and created a forwarding rule.  
**Data at risk:** Mailbox contents including vendor payment schedules (BEC risk).  
**Lateral movement:** no · **Confidence:** 0.9

**Affected hosts:** WS-FIN-017  
**Affected users:** j.alrashid

### Findings

- 197.210.53.14 is known-bad (credential-phishing, residential-proxy, aitm-infrastructure).
- login-microsoftonline-verify.com is known-bad (phishing, microsoft-lookalike, aitm).
- invoice-secure-portal.com is known-bad (phishing-sender, bec).
- Identity change on j.alrashid: oauth_consent — Consent granted to app 'PDF Viewer Pro' (unverified publisher) with Mail.Read and Mail.ReadWrite scopes
- Identity change on j.alrashid: mailbox_rule_created — Inbox rule 'RSS Feeds' forwards mail matching 'invoice|payment|wire' to ap.collections@proton-mail-secure.com and marks as read
- Same phishing campaign delivered to 3 mailbox(es); other recipients: m.hassan, s.alqahtani.

### Indicators of compromise

- `197.210.53.14` (ip)
- `login-microsoftonline-verify.com` (domain)
- `invoice-secure-portal.com` (domain)

### Timeline

| Time (UTC) | Source | Event |
|---|---|---|
| 05:02:11 | azure_ad | [auth_success] j.alrashid@WS-FIN-017: Interactive sign-in, MFA satisfied (push) |
| 05:12:40 | email_gateway | [email_delivered] j.alrashid@: Passed SPF/DKIM (attacker-owned domain), no attachment |
| 05:20:05 | web_proxy | [http_request] j.alrashid@WS-FIN-017: GET /common/oauth2 - category: uncategorised, allowed |
| 05:20:31 | web_proxy | [http_request] j.alrashid@WS-FIN-017: POST /common/oauth2/token - 2.1 KB form data submitted |
| 05:36:48 | azure_ad | [auth_success] j.alrashid@197.210.53.14: Non-interactive sign-in via replayed session token; MFA claim satisfied (token replay); user agent Chrome/Linux |
| 05:38:10 | azure_ad | [oauth_consent] j.alrashid@197.210.53.14: Consent granted to 'PDF Viewer Pro' (APP-7f31) with Mail.Read, Mail.ReadWrite |
| 05:41:02 | exchange_online | [mailbox_rule_created] j.alrashid@197.210.53.14: New-InboxRule 'RSS Feeds': forward to ap.collections@proton-mail-secure.com, MarkAsRead |
| 05:44:19 | exchange_online | [mailbox_item_accessed] j.alrashid@197.210.53.14: Downloaded attachment 'Q3 vendor payment schedule.xlsx' from folder Inbox/Payments |

## Response actions

| Action | Tier | Gate | Status | Verified | Decision |
|---|---|---|---|---|---|
| `iam.revoke_sessions_and_reset_password(user=j.alrashid)` | 2 | auto | executed | ✅ |  |
| `iam.enforce_mfa_reregistration(user=j.alrashid)` | 2 | auto | executed | ✅ |  |
| `iam.remove_mailbox_rules(user=j.alrashid)` | 1 | auto | executed | ✅ |  |
| `iam.revoke_oauth_grant(user=j.alrashid, app_id=APP-7f31)` | 1 | auto | executed | ✅ |  |
| `firewall.block_ip(ip=197.210.53.14)` | 1 | auto | executed | ✅ |  |
| `email_gateway.quarantine_message(message_id=MSG-88213)` | 1 | auto | executed | ✅ |  |
| `email_gateway.quarantine_message(message_id=MSG-88214)` | 1 | auto | executed | ✅ |  |
| `email_gateway.quarantine_message(message_id=MSG-88215)` | 1 | auto | executed | ✅ |  |
| `edr.scan_host(host=WS-FIN-017)` | 1 | auto | executed | – |  |

## Communications

- **ticket** → soc queue: Ticket TKT-7D3C6AA3 opened
- **chat** → #soc-incidents: INC-8800C5F1
- **chat** → #soc-incidents: INC-8800C5F1
- **email** → j.alrashid@corp.example: [Security] INC-8800C5F1 — Impossible travel: j.alrashid signed in from Lagos, NG 34 minutes after Riyadh, SA (asset owner notice)
- **email** → m.hassan@corp.example: [Security] INC-8800C5F1 — Impossible travel: j.alrashid signed in from Lagos, NG 34 minutes after Riyadh, SA (manager notice)
- **chat** → #soc-incidents: INC-8800C5F1

## State history

| Time | From | To | Actor | Note |
|---|---|---|---|---|
| 20:23:15 | new | triaged | commander | true_positive/high/0.97 → credential_compromise |
| 20:23:15 | triaged | investigating | commander |  |
| 20:23:15 | investigating | planning | commander |  |
| 20:23:15 | planning | containing | commander |  |
| 20:23:15 | containing | contained | commander | 9 action(s) executed and verified |
| 20:23:15 | contained | resolved | commander | contained; report written; ticket resolved pending post-incident review |

## Notes

- Playbook credential_compromise; notify roles ['user', 'manager', 'asset_owner']

_Generated by SOC Autopilot. Every tool call and decision is in the hash-chained audit log (`out/audit.jsonl`)._
