# Phase 5: Orchestrator — Implementation

## What Was Built

The Orchestrator adds an LLM-powered decision-maker on top of the existing
`execute_action()` pipeline. The human is no longer the only one who can
propose actions — the AI can now suggest tool calls, which go through the
exact same scope validation → approval gate → sandbox execution flow.

The human's role does NOT go away. Active_scan/exploit tier actions the AI
proposes still require explicit human approval via the existing Approvals
tab. The AI is a proposer, not an unsupervised actor.

## Architecture

```
User goal (chat) → Orchestrator (LLM) → proposes {tool, params}
    → SAME execute_action() as Phase 3-4 → scope validate → approval gate
    → sandbox execution → results
    → Orchestrator reads structured findings → decides next action or stops
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **LLM as proposer, not executor** | The Orchestrator never bypasses scope validation or the approval gate. It calls `execute_action()` which is the same function the Sandbox tab calls. |
| **Tool schemas from tools.yaml** | The LLM never sees or constructs raw shell commands — only structured `{tool_name, params}` selections, exactly like a human using the Sandbox tab. |
| **Compact state, not raw history** | Only structured findings (parsed output) are fed to the LLM, never raw stdout/stderr. Prevents context window bloat. |
| **JSON file session storage** | Same pattern as Phase 3's `.gateway_state.json` and Phase 4's `approvals.json`. Survives restart. |
| **One action per LLM turn** | The LLM proposes one action at a time. After execution, the result is incorporated and the LLM decides the next step. |

## LLM Configuration

The local LLM is configured via `.opencode/opencode.json`:

```json
{
  "provider": {
    "ollama": {
      "options": {
        "baseURL": "http://127.0.0.1:11434/v1"
      },
      "models": {
        "qwen2.5-coder:7b": { "name": "qwen2.5-coder:7b" }
      }
    }
  },
  "model": "ollama/qwen2.5-coder:7b"
}
```

The orchestrator's LLM client reads these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_API_BASE` | `http://127.0.0.1:11434/v1` | OpenAI-compatible API base URL |
| `LLM_API_KEY` | (empty) | API key if required |
| `LLM_MODEL` | `qwen2.5-coder:7b` | Model name to use |
| `LLM_MAX_TOKENS` | `2048` | Max tokens per response |
| `LLM_TIMEOUT` | `120` | HTTP timeout seconds |

This matches the existing Ollama setup already available on the dev machine.
To use a different provider (e.g. LM Studio, vLLM, OpenAI), set the
environment variables before starting the backend.

## Tool Schema Generation

The `tool_schemas.py` module reads `backend/tool_registry/tools.yaml` and
converts each tool into the OpenAI-compatible function-calling format:

```python
{
    "type": "function",
    "function": {
        "name": "nmap",
        "description": "Port and service scanner (passive - auto-executes) [attack_class: recon]",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP address or domain name"},
                "ports": {"type": "string", "description": "Port range (e.g. '1-1000')"}
            },
            "required": ["target"]
        }
    }
}
```

The description includes risk tier hints (`passive - auto-executes` vs
`active_scan - requires human approval`) and the attack class, so the LLM
understands safety constraints.

A special `finish_engagement` function is also generated — the LLM calls
this when it decides no further actions are needed, providing a summary.

## Compact State Design

The compact state sent to the LLM on each turn includes:

```python
{
    "engagement_id": str,
    "goal": str,                              # user's stated goal
    "findings_so_far": [...],                 # structured findings (parsed, no raw stdout)
    "tools_already_run": [str],               # tools used so far
    "pending_or_denied": [...],               # actions that were denied/expired
    "findings_truncated": int | None,         # set if >50 findings were truncated
}
```

The `_summarize_findings()` function extracts key fields from each finding
(type, tool, port, service, severity, etc.) and flattens them into a
compact representation. Raw `detail` dicts, `_job_id`, `_tool` metadata,
and any stdout/stderr are excluded.

Findings are **truncated at 50** in the compact state sent to the LLM (with
a `findings_truncated` indicator) to prevent context window overload.

## Orchestrator Loop

### `orchestrator_step(session_id, user_message=None)`

1. Load session state from JSON file
2. If user_message provided, update `goal`
3. Check for resolved pending approvals (approved + completed, or denied)
4. If still waiting for approval, return `waiting_for_approval` status
5. Call LLM with tool schemas + compact state
6. Parse LLM response:
   - **Tool call** → call `execute_action()` with the proposed tool and params
   - **finish_engagement** → set status to `completed`, store summary
   - **Error/unknown** → log error, return to active state
7. Handle `execute_action()` result:
   - `{"job_id": ...}` → poll job until completion, store findings
   - `{"status": "pending_approval", ...}` → store approval_id, set status
   - `{"error": ...}` → mark as denied, store reason
8. Save updated session, return UI state

### LLM Health Check

`GET /api/orchestrator/health` tests LLM connectivity by calling
`{LLM_API_BASE}/models`. Returns `{"connected": true/false, "model": ...}`.
The frontend shows a **Connect to LLM** button that calls this endpoint;
the conversation UI is disabled until connection is verified.

### `resolve_pending_approvals(session_id)` — no LLM call

1. Load session state, check resolved pending approvals (same as step 3 above)
2. Return UI state immediately — does NOT call the LLM
3. Used by `GET /sessions/{id}` so page refreshes and frontend polling don't
   trigger expensive LLM inference

## Approval Gate Integration

When `execute_action()` returns `pending_approval` for an active_scan tool:

1. The approval_id is stored in the session state
2. The frontend shows "Awaiting human approval" and polls the approval status
3. When the human approves via the Approvals tab, the job runs
4. On the NEXT orchestrator step (user sends another message), `_resolve_pending()`
   checks the approval status:
   - If **approved** and job completed → incorporate findings into `findings_so_far`
   - If **denied** → add to `pending_or_denied` so LLM won't retry
   - If **expired** → same as denied
5. The Orchestrator then calls the LLM with the updated state to decide the next action

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/orchestrator/health` | Check LLM connectivity |
| POST | `/api/orchestrator/sessions` | Create new session + first action (calls LLM) |
| POST | `/api/orchestrator/sessions/{id}/message` | Send message, trigger next step (calls LLM) |
| GET | `/api/orchestrator/sessions/{id}` | Get session state (no LLM call — uses `resolve_pending_approvals()`) |
| GET | `/api/orchestrator/sessions` | List all sessions |

### POST `/api/orchestrator/sessions`

```json
{"engagement_id": "eng-001", "goal": "scan for open ports"}
```

Returns the full session state after the first LLM action.

### POST `/api/orchestrator/sessions/{id}/message`

```json
{"message": "now check for web vulnerabilities"}
```

Returns the full session state after processing.

## Frontend

A new "AI Assistant" nav tab (`OrchestratorPanel.tsx`) provides a chat-style
interface:

- **Setup**: Connect to LLM button first, then engagement selector + goal input
- **Chat messages**: User messages and AI responses in a scrollable view
- **Action cards**: Proposed tool calls show tool name, target, params, outcome,
  and findings inline (collapsible) — findings are attached to the action card
  immediately on completion, not as a separate lazy message
- **Approval polling**: Automatically polls approval status when an action
  is pending, then polls job status when approved
- **Loading indicator**: Animated dots while LLM is thinking
- **Dark theme**: Matches existing panel conventions

## File / Module Locations

```
backend/
├── main.py                              # + orchestrator router
├── orchestrator/
│   ├── __init__.py
│   ├── tool_schemas.py                  # tools.yaml → LLM function schemas
│   ├── llm_client.py                    # Configurable OpenAI-compatible client
│   ├── state.py                         # Session state CRUD (JSON files)
│   ├── engine.py                        # orchestrator_step() loop
│   └── router.py                        # FastAPI endpoints
├── data/
│   └── sessions/                        # Session state storage (auto-created)
└── tests/
    └── test_orchestrator.py             # 20 tests

frontend/
├── src/
│   ├── App.tsx                          # + AI Assistant tab
│   ├── App.css                          # + Orchestrator styles
│   ├── hooks/
│   │   └── useApi.ts                    # + Orchestrator API types + functions
│   └── components/
│       └── OrchestratorPanel.tsx         # Chat-style AI assistant UI
```

## Tests (20 new, 145 total)

### Test groups

1. **TestToolSchemas** (3 tests) — schema count matches registry, descriptions
   and params are correct, system prompt includes state context
2. **TestLLMClient** (6 tests) — parse tool call JSON, code blocks, finish
   signal, plain text fallback, compact state excludes raw stdout, compact
   state does not balloon
3. **TestSessionState** (3 tests) — create, save/load, nonexistent session
4. **TestOrchestratorEngine** (6 tests) — passive auto-executes, active_scan
   returns pending_approval, out-of-scope denied, finish signal, pending
   resolved on next step, unknown tool handled gracefully
5. **TestIntegration** (2 tests) — schemas match registry, compact state
   truncates at 50

### Required verification scenarios

1. ✅ **Passive tool auto-executes** — nmap with mock LLM returns `job_id`,
   finds findings stored in session state (test: `test_passive_tool_auto_executes`)
2. ✅ **Active_scan returns pending_approval** — nikto returns
   `pending_approval`, verified no execution (test:
   `test_active_scan_returns_pending_approval`)
3. ✅ **Approve + follow-up** — pending approval resolved, findings
   incorporated, LLM called again with updated state (test:
   `test_pending_approval_resolved_on_next_step`)
4. ✅ **Out-of-scope denied** — scope validation error surfaced clearly,
   not silently swallowed (test: `test_out_of_scope_target_denied`)
5. ✅ **Compact state stays compact** — raw stdout/stderr excluded, max 50
   findings, `findings_truncated` indicator set (test:
   `test_compact_state_no_balloon`)
6. ✅ **Zero regressions** — all 145 tests pass (125 existing + 20 new)

## How to Run

```bash
# Start backend (with LLM config from .opencode/opencode.json)
LLM_API_BASE=http://127.0.0.1:11434/v1 LLM_MODEL=qwen2.5-coder:7b \
  uvicorn main:app --reload --port 8000

# Or without env vars (uses defaults)
uvicorn main:app --reload --port 8000

# Run orchestrator tests only
cd backend
python -m pytest tests/test_orchestrator.py -v

# Full suite (145 tests)
python -m pytest tests/ -v
```

## Frontend UI Fixes

### Completed badge shown as RUNNING

The `chat-status-badge` displayed "RUNNING" for both `executing` and `completed`
outcomes. Fixed to show "COMPLETED" (green) for completed, "RUNNING" for
executing only.

### LLM Connect button

The setup panel now shows a **Connect to LLM** button first. It calls
`GET /api/orchestrator/health` and only enables the engagement selector +
chat input on success. Displays `● LLM Connected` status once verified.

## Session Resume (Frontend)

The `OrchestratorPanel` now loads existing sessions on mount via
`listOrchestratorSessions()`. On page refresh:

1. Active and pending-approval sessions are shown as clickable **Resume** buttons
   above the new-session engagement selector
2. Clicking a session calls `getOrchestratorSession(id)` and rebuilds the
   chat history from `action_history` + `findings_so_far`
3. The user's initial `goal` is shown as the first user message
4. Each tool action in `action_history` becomes an assistant message with its
   outcome, params, and associated findings
5. If the session was waiting for approval, polling resumes automatically
6. New sessions refresh the session list so resumed sessions appear on
   subsequent page loads

Key functions added:
- `rebuildMessagesFromState(state)` — converts backend state to `MessageEntry[]`
- `handleResumeSession(sessionId)` — loads session and sets messages/engagement

## Live Testing Fixes

### Timezone-aware vs naive datetime comparison (scope_engine/validation.py)

Scope files created with naive datetimes (no timezone info, e.g.
`"2025-01-01T00:00:00"`) caused `TypeError: can't compare offset-naive and
offset-aware datetimes` when the LLM action's timestamp was generated with
`datetime.now(timezone.utc)` (which is timezone-aware).

**Fix**: Added `_ensure_tz(dt)` helper in `validation.py:12` that normalizes
naive datetimes to UTC via `dt.replace(tzinfo=timezone.utc)` before comparison.

### GET /sessions/{id} triggered LLM call

The GET endpoint called `orchestrator_step()` which calls the LLM — every page
refresh or frontend poll cost 5-10s of model inference time.

**Fix**: Added `resolve_pending_approvals()` in `engine.py:53` that only checks
resolved approvals without calling the LLM. GET endpoint now uses this function
instead of `orchestrator_step()`.

## Known Temporary State

- **LLM quality depends on local model** — qwen2.5-coder:7b may not
  always produce valid tool calls. The `_parse_tool_call()` function has
  fallback parsing for code blocks and regex-based extraction.
- **No Evidence Store / Reporter yet** — that's Phase 6
- **Sessions are stored as JSON files** — no cleanup mechanism yet for
  stale sessions (manual deletion from `data/sessions/`)
- **Polling for passive tools is synchronous** — the orchestrator step
  blocks until the job completes (max 600s timeout). For long-running
  passive scans, this could take a while.
- **Only one pending approval at a time** — the orchestrator will not
  propose new actions while an existing approval is pending. This is
  intentional to prevent flooding the Approvals tab.
