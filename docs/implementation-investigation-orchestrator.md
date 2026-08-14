# Phase 6: Objective-Driven Investigation Loop — Implementation

## What Was Built

Phase 5's orchestrator was a procedural "LLM → Tool → LLM → Tool" loop: the
LLM decided, executed, read findings, decided again. It followed instructions
correctly but did not *think*. Phase 6 replaces that with an **objective-driven
investigation loop**: the system observes, reasons, forms hypotheses, plans,
selects the highest-value next action, executes, learns, and repeats — the way
an experienced penetration tester works.

The key inversion: **the AI is objective-driven, not tool-driven.** Instead of
thinking "I should run Nmap", the investigation first decides "I need service
fingerprinting", then picks the best tool for that objective.

## Architecture

A shared **investigation blackboard** persists inside the session
(`session["investigation"]`). Lightweight reasoning components read from it,
parsers write to it, and every completed tool execution updates it. The LLM
receives a bounded summarization of this blackboard plus a **ranked candidate
action menu** instead of just "findings + tools already run".

```
                    ┌─────────────────────────────────────┐
                    │      INVESTIGATION BLACKBOARD        │
                    │ objective, phase, confidence,        │
                    │ facts, hypotheses, unknowns, assets, │
                    │ interesting ports/services/paths,    │
                    │ potential vulns, action_scores       │
                    └─────────────────────────────────────┘
                       ▲            │            ▲
                       │            ▼            │
              Mission/Investigation       Knowledge Manager
              Planner (planner.py)        (knowledge.py)
                       ▲            │            ▲
                       │            ▼            │
               Evidence Analyzer    │      Action Selector
               (analyst.py)         │      (selector.py)
                       ▲            ▼            │
                       │      LLM decides (llm_client.py)
                       │            │
                       │            ▼
                       │   engine.py: execute via existing pipeline
                       │   (scope → build_command → approval gate → sandbox)
                       └──── parser findings (enriched) ──┘
```

### The reasoning loop

`engine.py:_investigation_cycle()` runs **before every LLM call**:

1. **Observe** — `analyst.absorb(session)` folds new completed-tool findings
   into the blackboard (facts, assets, hypotheses, vulnerabilities). Idempotent
   per job via `_processed_jobs`.
2. **Plan** — `planner.initialize()` seeds the objective + initial unknowns
   from goal/scope on first use; `planner.advance(board, candidates)` recomputes
   phase (`recon → service_enum → web_recon → exploitation → report`),
   confidence, and the next objective.
3. **Select** — `knowledge.generate_candidates(board, scope_targets, goal)`
   derives "what is still missing" → a candidate action menu, each annotated
   with `info_gain`, `cost`, `risk`, `likelihood`. `selector.rank()` scores and
   sorts them into the shortlist `board["action_scores"]`.
4. **Decide** — the LLM reasons over the blackboard + ranked menu and proposes
   ONE complete param set (parked for human param-confirmation, unchanged from
   Phase 5).
5. **Execute** — the exact same pipeline as before: scope validate →
   `build_command` → approval gate (active/exploit) → sandbox.
6. **Learn** — when the job is terminal, findings are recorded; the next cycle's
   Observe step folds them back into the blackboard.

### Reasoning components (no tool agents)

| Component | File | Responsibility |
|-----------|------|----------------|
| Blackboard | `investigate/blackboard.py` | Shared memory; idempotent CRUD for facts/hypotheses/unknowns/assets/vulns |
| Mission + Investigation Planner | `investigate/planner.py` | Objective derivation; phase, confidence, next-objective |
| Evidence Analyzer | `investigate/analyst.py` | Folds tool findings into the board |
| Knowledge Manager | `investigate/knowledge.py` | Open gaps → candidate actions with value estimates |
| Action Selector | `investigate/selector.py` | Ranks candidates by expected value |
| Prompt | `investigate/prompts.py` | Objective-driven behavior contract |

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **No tool agents** | No NmapAgent/NiktoAgent/etc. Reasoning components are stateless heuristics that cooperate through the blackboard. The LLM stays the decision-maker; the heuristics only steer. |
| **Action prioritization, not hardcoded workflows** | Candidates are scored `0.40·gain + 0.25·likelihood + 0.15·phase_fit − 0.10·cost − 0.10·risk`. The best-scoring action wins — the system never hardcodes "run nmap, then nikto, then sqlmap". |
| **Planner runs after candidate generation** | Fixed a Phase-6 bug where `advance()` ran before the selector, so a fresh session with seeded hypotheses jumped straight to REPORT. `advance()` now takes the candidate list and only enters REPORT when the menu is empty. |
| **Parser enrichment is additive** | `enrich.py` appends `technology/confidence/interestingness/relationships/follow_ups` inside `finding["detail"]`. Existing finding keys and tests are untouched. |
| **Scope-engine still the gate** | `knowledge.py` never suggests out-of-scope hosts, but real safety is still enforced by `scope_engine.validate()` at execution time. |
| **Backward compatible** | Old sessions have `investigation: null`; `_build_compact_state()` simply omits the board. Approval gate, scope engine, sandbox, tool registry and param-confirmation are unchanged. |

## System Prompt

`investigate/prompts.py` is a full rewrite. It deliberately contains **no tool
names and no step-by-step workflow**. It defines:

- **IDENTITY** — an experienced pentester who leads an investigation, not a checklist.
- **OBJECTIVE** — from the engagement goal + blackboard (phase, facts, hypotheses, unknowns, next objective).
- **REASONING PRINCIPLES** — observe before acting, reason from evidence, form hypotheses, prefer information gain, learn and adapt, escalate deliberately.
- **DECISION PRIORITIES** — info gain > likelihood > cost > risk; use the ranked menu as guidance, decide yourself.
- **CONSTRAINTS** — scope only, no bypasses, one action at a time, wait for approvals, never re-propose done/denied actions, report honestly.
- **LEARNING BEHAVIOUR** — fold every result into the mental model each cycle; answer follow-ups directly.
- **RESPONSE FORMAT** — the existing JSON envelope `{intent: conversation|plan|execute, reply, action}`.

## Parser Enrichment

`tool_registry/parsers/enrich.py` attaches structured intelligence to every
finding:

| Field | Meaning | Example |
|-------|---------|---------|
| `technology` | Product inferred from version/name | `nginx`, `Apache`, `OpenSSH` |
| `confidence` | 0-1 that the observation is real | `0.7` (versioned port), `0.9` (credential) |
| `interestingness` | 0-1 relevance to the assessment | `1.0` (http/ssh/credential), `0.35` (uncommon service) |
| `relationships` | Links to other assets | `exposes_service`, `child_of`, `redirects_to`, `served_by` |
| `follow_ups` | Suggested next actions | http → nuclei+gobuster+nikto; sqlmap → confirm technique |

The Evidence Analyzer consumes these automatically.

## Files

- `backend/orchestrator/investigate/` — blackboard, planner, analyst, knowledge, selector, prompts
- `backend/orchestrator/engine.py` — `_investigation_cycle()`, reordered cycle
- `backend/orchestrator/llm_client.py` — compact state includes summarized blackboard + `candidate_actions` + `open_questions`
- `backend/orchestrator/state.py` — session gains `investigation: null` placeholder
- `backend/tool_registry/parsers/enrich.py` — shared enrichment
- `backend/tool_registry/parsers/*.py` — all 7 parsers call `enrich()`
- `backend/tests/test_investigate.py` — 32 tests

## Verification

- `python -m pytest tests/ -q` → **208 passed** (176 existing + 32 new).
- New tests cover: blackboard CRUD + dedup, planner phase/confidence/REPORT
  gating, analyst absorption + idempotency, knowledge candidate generation
  (recon/web/hydra/scope-gating), selector ranking, parser enrichment.
- Frontend: `npx oxlint src/` and `npx tsc -b` clean.

## Known Limitations

- The heuristics steer but the LLM decides; quality still depends on the local
  model (`qwen2.5-coder:7b`).
- The blackboard is advisory data for the LLM — it is not independently audited.
- Candidate cost/risk values are static per-tool estimates, not learned.
