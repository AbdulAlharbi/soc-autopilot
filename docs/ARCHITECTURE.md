# Architecture

## Goals

1. **Own the workflow.** A raw alert goes in; a contained incident, notified stakeholders, a resolved ticket and a report come out. No analyst has to touch the routine ones.
2. **Know the limits of its own authority.** The system must be able to say "this needs a human" and mean it — structurally, not as a prompt suggestion.
3. **Be trustworthy after the fact.** Every decision has evidence, every action has a verification, and the log cannot be quietly rewritten.
4. **Run anywhere.** Full workflow and tests without network or API keys; better reasoning when a model is available.

## Components

### Incident Commander (`commander.py`)

The orchestrator. It owns the incident state machine and sequences the specialists. It never calls a tool. After each phase it checkpoints both the incident (`out/incidents/INC-*.json`) and the simulated world (`out/world.json`) so that a crash or a deferred approval can be resumed by a fresh process (`socpilot decide … → commander.resume()`).

```
new ─▶ triaged ─┬─▶ closed_false_positive   (raise tuning ticket first)
                ├─▶ closed_benign
                └─▶ investigating ─▶ planning ─▶ containing ─┬─▶ contained ─▶ resolved
                                                             ├─▶ awaiting_approval ─▶ containing (resume)
                                                             └─▶ escalated  (denied / failed / unverifiable)
```

### Agents (`agents/`)

| Agent | Reads | Writes | Asks the brain for |
|---|---|---|---|
| **Triage** | assets, IAM, TI, allowlists, EDR, SIEM (±6h) | — | `TriageDecision`: verdict, severity, confidence, category, MITRE |
| **Investigator** | SIEM pivots (user→host→IP→owner→auth), EDR, TI on every IOC, mailbox changes, email campaign scope | — | `InvestigationDecision`: findings, root cause, lateral movement, data at risk, optional bounded follow-up queries |
| **Responder** | policy, playbooks | **all containment tools** | `ResponseDecision`: prune/add actions (adds are policy-assessed) |
| **Communicator** | IAM (who to notify), assets (owner, business service) | ticket, chat, mail | drafted notifications and approval requests |
| **Reporter** | the incident | report file | executive summary |

Write authority is enforced in `ToolRegistry.call` by the agent's `can_write` flag, not by convention.

### Signals

Triage does not hand the model a pile of JSON and hope. It computes named, boolean/numeric **signals** (`allowlisted_source`, `ti_malicious`, `suspicious_process_count`, `impossible_travel`, `mailbox_rule_created`, `service_account_interactive_logon`, `shadow_copy_deletion`, `exfil_staging`, `credential_access_attempted`, `off_hours`, …). Both brains reason over the same signals plus the raw evidence; the signals also go into the report so a reviewer can see *why*.

### Brain (`llm/`)

```python
class Brain(Protocol):
    def decide(task, context, schema: type[T]) -> T      # validated pydantic object
    def narrate(task, context) -> str                     # prose for humans
```

- `ClaudeBrain` — Anthropic Messages API, JSON-only responses validated against the schema, one repair round, then heuristic fallback (the rationale is tagged so the fallback is visible in the report and audit).
- `HeuristicBrain` — explicit rules. Deterministic, fast, no dependencies. Used for CI, demos, and as the production floor.

Both are recorded on every decision (`decided_by`) and on the incident (`brain`).

### Autonomy policy (`policy.py`, `config/policy.yaml`)

```
final_tier = base_tier(tool.op)
           + (critical asset ? +1) + (production ? +1)          # only if base_tier ≥ bump_min_base_tier
           + (privileged ? +1) + (service acct ? +1) + (VIP ? +1)
           capped at 3

requires_approval = op ∈ never_automate
                  ∨ op ∈ always_require_approval
                  ∨ final_tier > auto_execute_max_tier
                  ∨ triage.confidence < min_confidence_for_auto
                  ∨ auto_actions_executed ≥ max_auto_actions_per_incident
```

The bump threshold matters: killing one process or collecting forensics on a production server is *not* made high-risk by the server's importance, but isolating it or disabling its accounts is.

### Playbooks (`data/playbooks/*.yaml`)

Templates keyed by triage category. Parameters render from the Investigator's context: `{user}`, `{host}`, `{each:malicious_ips}` (one action per value), `when: signals.mailbox_rule_created` (conditional). Unresolvable placeholders drop the action rather than sending garbage to a system. The brain reviews the expanded plan and may prune or add; adds must exist in the containment catalogue and are policy-assessed like everything else.

### Tool registry and mocks (`tools/`)

`MockEnvironment` holds stateful simulations of nine systems loaded from `data/fixtures/`. They are stateful on purpose: isolating a host changes what `edr.get_host` returns afterwards, which is what lets the Responder verify its own work. `ToolRegistry` is the single call path: it validates the operation, enforces read/write authority, records the call and (truncated) result in the audit log.

### Human gateways (`humans.py`)

`ApprovalGateway.request(incident, action) -> Approval | None`. Interactive (terminal), scripted (tests/demos) and deferred (persist and resume later) implementations. A Slack or ticket-comment gateway is the same interface.

### Audit (`audit.py`)

JSON lines, each carrying the SHA-256 of `prev_hash + entry`. `AuditLog.verify()` walks the chain. Tests include a tampering case.

## Data flow for one incident (ransomware scenario)

1. Alert: shadow copies deleted on `SRV-ERP-01` by `svc_backup`.
2. **Triage** — asset is critical/production; user is a service account with a forbidden interactive logon; EDR shows `vssadmin` and unsigned `rclone` in `%TEMP%`; SIEM shows `wbadmin`/`bcdedit`. Signals fire → `true_positive / critical / 0.97 / ransomware`.
3. **Investigator** — pivots on the RDP source IP to `WS-IT-ADM-03`, whose owner `r.otaibi` had a VPN login from a ransomware-affiliate IP after repeated MFA pushes; follows `svc_backup` to `SRV-FS-03`. Three hosts, two users, lateral movement, exfil in progress. Builds the timeline and the playbook context (`malicious_ips`, `malicious_pids`, `affected_hosts`, `compromised_users`).
4. **Responder** — expands the ransomware playbook into 10 actions; policy tiers them: kill×2, block×2, isolate workstation, forensics → **auto**; isolate ERP, isolate file server, disable service account, reset privileged admin → **human**.
5. **Containment** — the six autonomous actions run and are verified. Four approval requests go to `#soc-approvals` with rationale, tier reason, business service and "already done".
6. **Human** — approves/denies/defers. Deny → `escalated`, IR lead emailed, residual risk in the report. Approve → the actions run, verify → `resolved`.
7. **Reporter** — writes `out/reports/INC-*.md`; Communicator resolves the ticket.
