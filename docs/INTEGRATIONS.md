# Integrations — replacing the mocks

Each mock in `src/socpilot/tools/environment.py` exposes the operations the agents need. A real adapter implements the same methods against the vendor API and is registered in `ToolRegistry._register_all`. Nothing in the agents, policy or playbooks changes.

| Mock class | Operations | Real-world equivalents |
|---|---|---|
| `SIEM` | `search`, `auth_history` | Splunk (`/services/search/jobs`), Microsoft Sentinel (KQL via Log Analytics API), Elastic (`_search`) |
| `EDR` | `get_host`, `isolate_host`, `kill_process`, `scan_host`, `collect_forensics` | CrowdStrike Falcon (`/devices/entities/devices-actions/v2` contain, RTR `kill`), Microsoft Defender for Endpoint (`/machines/{id}/isolate`, live response), SentinelOne |
| `IAM` | `get_user`, `revoke_sessions_and_reset_password`, `enforce_mfa_reregistration`, `remove_mailbox_rules`, `revoke_oauth_grant`, `disable_user` | Microsoft Entra ID / Graph (`revokeSignInSessions`, `authentication/methods`, `oauth2PermissionGrants`), Exchange Online (`Remove-InboxRule`), Okta |
| `ThreatIntel` | `lookup` | VirusTotal, MISP, Recorded Future, vendor TI feeds |
| `EmailGateway` | `find_messages`, `quarantine_message` | Proofpoint TRAP, Microsoft Defender for Office 365 (`/security/collaboration/analyzedEmails` + remediation), Mimecast |
| `Firewall` | `block_ip`, `block_subnet` | Palo Alto (EDL or `/restapi/.../address` + policy), Fortinet, Zscaler, cloud security groups |
| `Ticketing` | `create_ticket`, `update_ticket`, `resolve_ticket` | Jira, ServiceNow SIR, TheHive |
| `Chat` | `post` | Slack (`chat.postMessage`, Block Kit buttons → `ApprovalGateway`), Microsoft Teams |
| `Mail` | `send` | Graph `sendMail`, SES, SMTP |
| `Allowlists` | `match_scanner` | CMDB / change-management system (ServiceNow CHG records) |

## Approval gateway

`humans.ApprovalGateway.request(incident, action)` returns an `Approval` or `None` (deferred). For Slack: post the request with two buttons, return `None`, and have the interaction webhook call `socpilot decide <incident> <action> --approve/--deny --as <slack user>` (or the equivalent library call `IncidentCommander.resume`). Approver identity should come from the chat platform, not from the message body.

## Operational notes

- **Idempotency.** Key incidents on the upstream alert id; a re-delivered alert should attach to the open incident, not create a second one.
- **Concurrency.** One incident per worker; the world state file becomes the real systems, so drop `world.json` and read fresh.
- **Secrets.** Vendor credentials in a vault; the agents never see them — the adapters do.
- **Rate limits.** The policy's `max_auto_actions_per_incident` is a safety budget, not a rate limiter; add per-tool backoff in the adapters.
- **Evaluation before autonomy.** Replay historical alerts with `--brain claude` and `--brain heuristic`, diff verdicts and plans against analyst outcomes, and only then raise `auto_execute_max_tier`.
