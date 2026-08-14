# Phase 1: Scope Engine — Implementation

## What Was Built

The Scope Engine is the foundation of the AI Red Team Platform. It defines
the legal/contractual boundary of a security engagement and validates every
action against it before anything executes.

### Scope File Schema

Scope files are stored as JSON on disk under `backend/data/scopes/{engagement_id}/scope_v{version}.json`.
They are **immutable once created** — any edit creates a new version, never overwrites.

```
engagement_id            str               # Unique identifier (e.g. eng-001)
engagement_name          str               # Human-readable name
version                  int               # Auto-incremented (starts at 1)
targets                  list[str]         # IPs, CIDRs, or domains in scope
excluded_targets         list[str]         # Carve-outs inside an otherwise in-scope range
start_time               str (ISO 8601)    # Authorization window start
end_time                 str (ISO 8601)    # Authorization window end
allowed_attack_classes   list[str]         # From: recon, web, network, exploitation, social_eng, mitm
authorization_contact    {name, email, role}  # Who approved this
emergency_contact        str               # Kill-switch contact (name + phone/email)
rate_limit               int | null        # Optional max req/s
notify_before_exploit    bool | null       # Extra manual gate for exploitation class
created_at               str (ISO 8601)    # Timestamp of creation
```

### validate() Function — Core Contract

```python
validate(action: dict, scope: dict) -> {"allowed": bool, "reason": str}
```

**Parameters:**

- `action`: dict with keys:
  - `engagement_id` (str)
  - `target` (str) — IP address, CIDR notation, or domain name
  - `attack_class` (str) — one of the 6 allowed classes
  - `timestamp` (datetime or ISO string)

- `scope`: dict — a loaded scope file dict (same schema as above)

**Returns:**
```
{"allowed": true,  "reason": "Action is within scope"}
{"allowed": false, "reason": "..."}  # Explains which check failed
```

**Validation priority (short-circuits on first failure):**

1. **Exclusion check** — if target matches an `excluded_target` entry, deny
2. **Scope check** — if target is not in `targets`, deny
3. **Time window** — if `timestamp` is outside `[start_time, end_time]`, deny
4. **Attack class** — if `attack_class` not in `allowed_attack_classes`, deny
5. **Allow** — all checks passed

**Target matching logic** (`scope_engine/validation.py:_matches`):

- **IP/CIDR**: Uses Python `ipaddress` module. Single IP matches exactly; CIDR
  matches if the action IP falls within the network range.
- **Domain**: Exact match, subdomain match (e.g. `example.com` matches
  `sub.example.com`), and wildcard prefix match (`*.example.com` matches
  `sub.example.com`).
- **Exclusion wins**: If a target is inside an allowed CIDR but is also
  individually excluded, validation returns `false` with a reason explaining
  the exclusion.

### File / Module Locations

```
backend/
├── main.py                          # FastAPI app entry point
├── scope_engine/
│   ├── __init__.py
│   ├── models.py                    # Pydantic models, target validation
│   ├── validation.py                # validate() + target matching helpers
│   ├── storage.py                   # File I/O, versioning, list/read scopes
│   └── router.py                    # FastAPI REST endpoints
├── data/scopes/                     # Scope file storage (gitignored)
└── tests/
    └── test_scope_engine.py         # 22 tests covering all 5 required cases

frontend/
├── src/
│   ├── main.tsx                     # React entry point
│   ├── App.tsx                      # Layout + tab navigation
│   ├── App.css                      # Component styles (dark theme)
│   ├── index.css                    # Global reset + CSS variables
│   ├── hooks/
│   │   └── useApi.ts                # API client functions + types
│   └── components/
│       ├── ScopeForm.tsx            # Create scope with inline validation
│       ├── ScopeViewer.tsx          # View engagement scope details
│       ├── ValidatePanel.tsx         # Test validate() with presets + history
│       └── StatusBadge.tsx          # Allowed/Denied status indicator
```

## How to Run

### Backend

```bash
cd backend
pip install fastapi uvicorn pydantic pytest
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev    # serves on http://localhost:5173
```

### Tests

```bash
cd backend
python -m pytest tests/ -v
```

## Frontend Structure & Future Phase Integration

This frontend is the **permanent foundation** for all phases. Future phases
add new views by extending the existing structure — never replacing it.

### Current structure

```
frontend/src/
├── App.tsx              # Root layout, tab navigation. Future phases add tabs here.
├── components/          # Each phase adds its own component directory
│   ├── ScopeForm.tsx    # Phase 1
│   ├── ScopeViewer.tsx  # Phase 1
│   ├── ValidatePanel.tsx # Phase 1
│   └── StatusBadge.tsx  # Shared component
├── hooks/
│   └── useApi.ts        # All API calls. Future phases add new API functions here.
├── App.css              # Component styles organized by section
└── index.css            # CSS variables, reset, scrollbar styles
```

### Where future phases should plug in

- **Phase 2 (Tool Registry)**: Add `components/ToolRegistry.tsx` and a "Tools"
  nav tab in `App.tsx`. Add API functions in `useApi.ts`.
- **Phase 3 (Sandbox Executor)**: Add `components/SandboxPanel.tsx` and a
  "Sandbox" tab. Add API functions.
- **Phase 4 (Approval Gate)**: Add `components/ApprovalGate.tsx` in a
  "Pending Actions" tab. The `StatusBadge` component can be reused (add an
  "approved"/"pending" variant).
- **Phase 5 (Orchestrator)**: Add a chat-like component for the LLM interaction.
- **Phase 6-7 (Evidence Store, Reporter)**: Add read-only viewer tabs.

Each phase should follow the same patterns:
- One component file per major view
- API functions in `hooks/useApi.ts`
- CSS in `App.css` (add new sections at the bottom)
- Nav tab entry in `App.tsx`

### CSS Theme System

All colors and fonts are defined as CSS custom properties in `index.css`:
- `--bg-primary`, `--bg-secondary`, `--bg-card` — dark backgrounds
- `--accent-green`, `--accent-red`, `--accent-amber` — status colors
- `--accent-blue`, `--accent-purple` — accent/action colors
- `--font-mono` — monospace for technical data (targets, IDs, timestamps)
- `--font-sans` — UI text

Phase 2+ should reuse these variables rather than adding new color values.

## UI Behaviors

### Inline Validation (ScopeForm)

Every field in the scope creation form validates on both `onChange` and
`onBlur`, not just on submit:

- **Targets / Excluded Targets textareas**: Each line is validated as a
  CIDR, IP, or domain. Invalid lines produce an immediate inline error
  message below the field. `onChange` re-validates as you type; `onBlur`
  catches final focus-loss.
- **End Time**: Validated against Start Time whenever either changes or
  the end time field loses focus. Shows "End time must be after start time"
  inline.
- **All required text fields**: Validated on blur for non-empty.
- **Rate Limit**: Validated as a positive integer on blur.
- **Attack Classes**: Validated on any checkbox toggle.

Submit-time `validate()` still runs as a fallback, catching any edge case
the per-field validation missed.

### Existing Engagement Auto-Populate (ScopeForm)

When the Engagement ID field loses focus (`onBlur`), the form calls the
backend API to check if that ID already exists. If found, all form fields
are populated with the existing scope's data (targets, excluded targets,
time window, attack classes, contacts, rate limit, notify-before-exploit).
The targets and excluded targets are joined with newlines into the textareas.

A blue banner appears at the top: "Existing engagement found — editing will
create version N+1" where N is the current latest version. The submit button
text also updates to "Create Version N+1".

If the ID does not exist, the form stays blank and no banner is shown.
Typing over the engagement_id field clears the loaded state immediately.

### Validate Panel — "Now" Button

The timestamp field in the Validate Panel has a "Now" button next to it.
Clicking it resets the timestamp to the current time without the user needing
to type or pick a new value. This is useful when testing against the current
time window.

### Validate Panel — Stale Result Indicator

After running a validate() test and seeing a result (allowed/denied + reason),
if the user edits any input field (target, attack class, timestamp, or
engagement), the displayed result is replaced with a grayed-out "STALE"
indicator. The text reads: "Inputs changed — re-run validation to see updated
result". This prevents the misleading appearance of an unchanged result when
the inputs have changed.

The stale state is cleared and a fresh validation runs when the user clicks
"Validate Action" again.

## Decisions & Tradeoffs

| Decision | Rationale |
|----------|-----------|
| **JSON storage (not YAML)** | JSON is natively parseable by both Python and JS without extra deps; Pydantic serializes to it directly |
| **File-based storage** (not SQLite) | Scope files are small (< 100KB), checked rarely after creation, and versioning is simpler with files. SQLite is reserved for the Evidence Store in Phase 6 |
| **Exclusion checked before scope** | Ensures test case (e) passes: an excluded target inside a wide CIDR is denied with "excluded" reason rather than being ambiguous |
| **Domain subdomain matching** | `example.com` implicitly matches `sub.example.com` — common in pentesting where a scope domain covers all subdomains. Explicit wildcard `*.example.com` also supported |
| **Pydantic models for validation** | Inline field validators (CIDR format, end > start, at least one attack class) catch errors at the API boundary before they reach storage |
| **React + Vite** | Standard modern frontend stack, fast dev server, TypeScript support out of the box, easy to extend with new pages/components |
| **onChange + onBlur validation** | onChange gives instant feedback as user types; onBlur catches the final value when they leave the field. Both together avoid stale errors without being overly aggressive. |
| **Existing engagement auto-populate on blur** | Fetches on blur (not onChange) to avoid hammering the API on every keystroke. The user finishes typing the ID, then the form loads the data. |
| **Stale result indicator** | Prevents the subtle bug where a user sees a result badge + text that no longer corresponds to the current inputs, which would cause incorrect trust in the validate() panel. |
