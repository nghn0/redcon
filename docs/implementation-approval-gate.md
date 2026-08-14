# Phase 4: Approval Gate — Implementation

## What Was Built

The Approval Gate inserts a human-in-the-loop checkpoint between scope
validation and actual execution. Passive-tier tools (nmap, subfinder) are
auto-approved and execute immediately — no change from Phase 3.
Active-scan and exploit-tier tools require explicit human approval before
any Docker container starts.

## Data Model

Approval requests are stored durably in `backend/data/approvals.json`,
a JSON file that survives backend restart (same pattern as Phase 3's
`.gateway_state.json` fix for Bug 3).

```python
{
    "approval_id": "apr-0001",
    "engagement_id": "eng-001",
    "tool_name": "nikto",
    "params": {"target": "127.0.0.1", "port": "80"},
    "risk_tier": "active_scan",
    "attack_class": "web",
    "target": "127.0.0.1",
    "requested_at": "2026-07-20T12:00:00+00:00",
    "status": "pending",
    "decided_by": null,
    "decided_at": null,
    "deny_reason": null,
    "result_job_id": null,
}
```

**Status lifecycle**: `pending` → `approved` | `denied` | `expired`

## Tiered Approval Logic

The check is inserted in `execute_action()` in `sandbox_executor/executor.py`,
immediately after scope validation passes and before `build_command()`:

```
execute_action(engagement_id, tool_name, params)
    │
    ├── 1. Load scope, build action, scope validate (UNCHANGED)
    │       FAIL → return error (unchanged)
    │       PASS → continue
    │
    ├── 2. NEW: Approval Gate check in execute_action()
    │       risk_tier == "passive" → auto-approved, logged, continue immediately
    │       risk_tier == "active_scan" / "exploit" →
    │           create_approval() → return {"status": "pending_approval", "approval_id": "..."}
    │           DO NOT proceed to build_command() or Docker
    │
    ├── 3. [passive only, or via approve endpoint] build_command() → SandboxExecutor.run()
    └── 4. Return job_id
```

### Tier assignments (from tools.yaml, unchanged)

| Tool | risk_tier | Attack Class | Behavior |
|------|-----------|--------------|----------|
| nmap | passive | recon | Auto-approved |
| subfinder | passive | recon | Auto-approved |
| nuclei | active_scan | web | Requires approval |
| gobuster | active_scan | web | Requires approval |
| nikto | active_scan | web | Requires approval |
| sqlmap | active_scan | web | Requires approval |
| hydra | active_scan | network | Requires approval |

**Exploit tier**: No tools currently use this tier, but the logic already
handles it identically to `active_scan` — it would require human approval.
This is the safest default; if future exploit-tier tools are added, they
automatically get the human-in-the-loop gate without code changes.

### Auto-approval logging

When a passive-tier tool auto-approves, no approval record is created —
execution proceeds as in Phase 3. The only observable difference is a
single `risk_tier` check in `execute_action()`.

## Expiry

Pending approval requests expire after **30 minutes**. This is enforced
in `get_approval()` and `approve_approval()` — both check
`_is_expired(requested_at)` and auto-transition to `"expired"` status
before returning.

**Rationale for 30 minutes**: Pending approvals represent time-sensitive
decisions. The engagement scope could be versioned, the target's behavior
could change, or the operator's intent could drift. 30 minutes gives a
human ample time to review and decide while keeping the window short
enough that context is unlikely to be stale. This matches real-world
pentest ops where authorization windows and scope changes happen on the
scale of hours, not minutes.

After expiry:
- `GET /api/approvals/{id}` returns `status: "expired"`
- `POST /api/approvals/{id}/approve` returns HTTP 400 with message
- The user must re-submit the action to get a fresh pending request

## Durable Storage

All approval state is written to `backend/data/approvals.json`:

- Every `create_approval()`, `approve_approval()`, `deny_approval()`, and
  `set_approval_job_id()` writes to the file immediately
- `get_approval()` and `list_approvals()` read from the file on every call
- In-memory `_approvals` dict is a secondary cache only (used as fallback)
- Same durability principle as Phase 3's `.gateway_state.json` — the file
  is the source of truth, so a backend restart loses no state

## API Endpoints

### `GET /api/approvals`
Returns list of pending approval requests across all engagements.
Query params:
- `engagement_id` — filter to one engagement
- `include_decided=true` — include approved/denied/expired records

### `POST /api/approvals/{approval_id}/approve`
Approves a pending request AND triggers execution.
- Re-validates scope at approval time (safety — scope may have changed)
- Calls `build_command()` + `SandboxExecutor.run()`
- Returns `{"status": "approved", "job_id": "sbox-0001", "approval_id": "apr-0001"}`
- Returns HTTP 400 if expired, already decided, or scope validation fails
- Returns HTTP 500 if Docker execution fails

### `POST /api/approvals/{approval_id}/deny`
Denies a pending request. Body:
```json
{"reason": "Not needed", "decided_by": "ui-user"}
```
Returns the updated approval record.

### `GET /api/approvals/{approval_id}`
Returns single approval request detail/status.

## Integration with execute_action()

The change in `execute_action()` is minimal — one `if` block inserted
after scope validation passes:

```python
risk_tier = tool.get("risk_tier", "active_scan")
if risk_tier in ("active_scan", "exploit"):
    approval = create_approval(
        engagement_id=engagement_id,
        tool_name=tool_name,
        params=params,
        risk_tier=risk_tier,
        attack_class=attack_class,
        target=target,
    )
    return {"status": "pending_approval", "approval_id": approval["approval_id"]}
```

The passive path is completely unchanged — same code path, same behavior.

When the approve endpoint triggers execution, it:
1. Loads and re-validates the scope (scope may have been versioned)
2. Builds the command from the stored params
3. Calls `SandboxExecutor.run()` directly

## Frontend Changes

### SandboxPanel.tsx
- When `executeAction()` returns `{status: "pending_approval", approval_id}`,
  the UI shows a yellow "Pending approval" card instead of a job progress UI
- Polls the approval status via `getApproval()` every 2 seconds
- When approved (detects `result_job_id` in approval), auto-transitions to
  the normal job polling flow — same UX as Phase 3
- When denied/expired, shows the terminal state

### ApprovalsPanel.tsx (new)
- Lists all pending approval requests across engagements
- Each card shows: tool name, target, risk tier badge, attack class,
  params (collapsible), requested time, and Approve/Deny buttons
- Approve triggers the backend endpoint, then polls the resulting job
  and displays job output inline
- Deny prompts for an optional reason
- Auto-refreshes every 5 seconds
- Filter dropdown by risk tier

### App.tsx
- New "Approvals" nav tab, active state styled the same as other tabs

### useApi.ts
- `ApprovalRequest` and `ApproveResult` TypeScript interfaces
- `listApprovals()`, `getApproval()`, `approveApproval()`, `denyApproval()` API functions

## File / Module Locations

```
backend/
├── main.py                          # + approval_gate router, phase 4 badge
├── approval_gate/
│   ├── __init__.py
│   ├── gate.py                      # Data model, durable storage, CRUD, expiry logic
│   └── router.py                    # FastAPI REST endpoints for approvals
├── sandbox_executor/
│   └── executor.py                  # execute_action() modified with approval gate check
├── data/
│   └── approvals.json               # Durable approval storage (auto-created)
└── tests/
    └── test_approval_gate.py        # 18 tests

frontend/
├── src/
│   ├── App.tsx                      # + Approvals tab
│   ├── App.css                      # + Approval panel/rules styles
│   ├── hooks/
│   │   └── useApi.ts                # + Approval API types + functions
│   └── components/
│       ├── SandboxPanel.tsx         # + pending_approval handling, polling
│       └── ApprovalsPanel.tsx       # New: approval list with Approve/Deny UI
```

## How to Test

### Test commands

```bash
cd backend

# Full suite (125 tests - all phases)
python -m pytest tests/ -v

# Approval gate only (18 tests)
python -m pytest tests/test_approval_gate.py -v

# Scope Engine (22 tests)
python -m pytest tests/test_scope_engine.py -v

# Tool Registry (61 tests)
python -m pytest tests/test_tool_registry.py -v
```

### Manual test flow (required, tests 1-5)

1. **Passive auto-executes**: Run nmap through the Sandbox tab → see
   immediate job execution, no approval step, identical to Phase 3.
2. **Active_scan creates pending**: Run nikto → see "Pending approval"
   yellow card with approval ID. Verify `docker ps` shows no new
   `redteam-tools` containers during this state.
3. **Approve → executes**: Switch to Approvals tab → click Approve →
   job starts running, results appear.
4. **Deny → never executes**: Submit another active_scan tool → go to
   Approvals tab → click Deny → confirm `docker ps` shows no new
   containers, status shows "denied".
5. **Expiry**: Submit an action, wait 30 minutes (or use simulated
   time-travel in tests), confirm it auto-transitions to "expired".

### Test results (125 passing)

```
tests/test_approval_gate.py          18 passed
tests/test_scope_engine.py           22 passed
tests/test_tool_registry.py          61 passed
tests/test_sandbox_executor.py       24 passed
```

All 7 required verification scenarios pass:
1. ✅ Passive (nmap) auto-executes — test_passive_tool_auto_executes
2. ✅ Active_scan creates pending — test_active_scan_returns_pending_approval
3. ✅ Approve → executes — test_5_approve_approval + test_13_set_job_id
4. ✅ Deny → never executes — test_7_deny_approval + test_9_cannot_approve_after_deny
5. ✅ Expiry — test_11_expiry_auto_transitions + test_12_cannot_approve_expired
6. ✅ State survives restart — test_14_durable_storage_survives_reload
7. ✅ No regressions — all 125 tests pass (same 107 from Phase 3 + 18 new)

## Decisions & Tradeoffs

| Decision | Rationale |
|----------|-----------|
| **Separate approval_gate module** | Keeps the gate logic independent of sandbox/executor internals; `execute_action()` imports just one function |
| **File-based JSON storage** | Same pattern as Phase 3's `.gateway_state.json` — survives restart, no DB dependency, trivially inspectable |
| **RLock for thread safety** | `create_approval()` acquires the lock and calls `_get_next_approval_id()` which also acquires it — RLock prevents deadlock. Non-reentrant Lock would hang on this pattern |
| **Scope re-validation on approve** | Safety: the scope may have been versioned since the pending request was created. Re-validating at approve time ensures the action is still within the engagement's current boundary |
| **30-minute expiry** | Long enough for human review, short enough that context drift (scope changes, target changes) is unlikely. Matches real-world session timeout conventions |
| **No approval record for passive tools** | Keeps the approvals file clean — passive tools leave no trace in the approval system since they never pause. The only change is a risk_tier check in execute_action() |
| **execute_action() modified in place** | The change is a single `if risk_tier in ("active_scan", "exploit"):` branch inserted after scope validation. The passive path is line-for-line identical to Phase 3 |
