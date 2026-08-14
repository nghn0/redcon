import threading
from datetime import datetime, timezone

from tool_registry.registry import get_tool, ToolRegistryError
from tool_registry.capabilities import resolve as resolve_capability
from sandbox_executor.executor import execute_action, SandboxExecutor
from approval_gate.gate import get_approval
from .llm_client import decide as llm_decide
from .intent import EXECUTION, classify_intent
from .state import load_session, save_session, list_sessions
from .investigate import planner, analyst, knowledge, selector
from scope_engine import storage as scope_storage

# Per-session reentrant locks: serialize auto-drive worker and user-triggered
# steps for the same session so two threads never drive it concurrently.
_step_locks: dict[str, threading.RLock] = {}
_step_locks_guard = threading.Lock()

_AUTO_CONTINUE_INTERVAL = 5


def _session_lock(session_id: str) -> threading.RLock:
    with _step_locks_guard:
        if session_id not in _step_locks:
            _step_locks[session_id] = threading.RLock()
        return _step_locks[session_id]


def _investigation_cycle(session: dict) -> dict:
    """One full deterministic cycle of the investigation loop — Observe ->
    Analyze -> Plan -> Select. Runs BEFORE the LLM so the model always sees an
    up-to-date blackboard and a ranked candidate menu. Pure and side-effect
    free apart from the session's blackboard."""
    scope = _load_scope_for_session(session)
    scope_targets = [
        str(t).strip() for t in (scope and scope.get("targets") or []) if str(t).strip()
    ]

    planner.initialize(session, scope=scope)
    board = analyst.absorb(session)

    goal = session.get("goal", "")
    candidates = knowledge.generate_candidates(board, scope_targets or [], goal=goal)

    # Planner runs after the candidate menu is built so the phase/next-objective
    # computation can see what valuable work still remains (a candidate-less
    # board is the only thing that justifies the REPORT phase). The selector
    # ranks candidates last and writes the shortlist the LLM reasons over.
    planner.advance(board, candidates=candidates)
    board["action_scores"] = selector.rank(candidates, board)
    return board


def _load_scope_for_session(session: dict):
    engagement_id = session.get("engagement_id")
    if not engagement_id:
        return None
    try:
        return scope_storage.load_scope(engagement_id)
    except Exception:
        return None


def orchestrator_step(session_id: str, user_message: str | None = None) -> dict:
    with _session_lock(session_id):
        session = load_session(session_id)
        if session is None:
            return {"error": f"Session '{session_id}' not found"}

        save_session(session)

        _resolve_pending(session)

        if _has_active_pending(session):
            session["status"] = "pending_approval"
            save_session(session)
            return _ui_state(session)

        # Param-confirmation gate: a proposed tool call sits here until the user
        # explicitly confirms (or overrides) the params via /params-confirm or
        # dismisses it via /params-cancel. Never auto-advance past it.
        pending_confirm = session.get("_pending_param_confirm")
        if pending_confirm:
            if user_message:
                session["action_history"].append({
                    "type": "user",
                    "content": user_message,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                session["action_history"].append({
                    "type": "chat",
                    "content": (
                        f"I'm waiting for you to confirm the params for "
                        f"**{pending_confirm['tool_name']}**. Use the confirmation "
                        f"card above, or type \"cancel\" to dismiss it."
                    ),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            save_session(session)
            return _ui_state(session)

        if user_message and session.get("action_history"):
            # Persist the user's message so the model has conversation context
            # for follow-ups ("why is that", "and then?", etc.). Skipped on the
            # initial creation call where the goal already represents the ask.
            session["action_history"].append({
                "type": "user",
                "content": user_message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        # Intent is deliberately decided before the investigation loop.  Only
        # an explicit execution request may build a tool candidate menu or
        # receive a tool-capable LLM prompt.
        # Legacy/internal callers may start a fresh session without passing the
        # goal as ``user_message``.  Treat that initial goal as the first user
        # message; later no-message calls remain auto-drive continuations only.
        if user_message is None and not session.get("action_history"):
            # Compatibility for the internal/legacy "start session" call.
            # The HTTP endpoint passes the goal as a real user message, so all
            # user-originated content still goes through classification.
            interaction_intent = EXECUTION
        else:
            interaction_intent = classify_intent(user_message, session)

        if interaction_intent == EXECUTION:
            # Investigation loop: Observe -> Analyze -> Plan -> Select. Folds
            # new job evidence into the blackboard and generates candidate
            # actions only after execution has been explicitly selected.
            _investigation_cycle(session)

        llm_response = llm_decide(
            session, user_message=user_message, interaction_intent=interaction_intent
        )

        # Defense in depth: a model response can never create a proposal when
        # this turn was classified as conversation or planning, even if a model
        # ignores its prompt and emits a tool call.
        if interaction_intent != EXECUTION and llm_response.is_tool_call:
            llm_response.is_tool_call = False
            llm_response.finish = False
            llm_response.intent = interaction_intent
            if not llm_response.content:
                llm_response.content = "I can explain or plan that. Tell me explicitly when you want me to run it."

        # Plain-text reply. If the model signalled finish_engagement (parsed
        # JSON), end the session. Otherwise treat it as a normal conversational
        # reply and keep the session active.
        if not llm_response.is_tool_call:
            if getattr(llm_response, "finish", False):
                session["status"] = "completed"
                session["summary"] = llm_response.content
                session["action_history"].append({
                    "type": "summary",
                    "content": llm_response.content,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                session["auto_drive"] = False
                save_session(session)
                return _ui_state(session)

            session["status"] = "active"
            session["auto_drive"] = any(
                a.get("outcome") == "executing" for a in session["action_history"]
            )
            session["action_history"].append({
                "type": "chat",
                "content": llm_response.content,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            save_session(session)
            return _ui_state(session)

        if llm_response.tool_name == "finish_engagement":
            session["status"] = "completed"
            session["summary"] = llm_response.arguments.get("summary", "Engagement complete.")
            session["action_history"].append({
                "type": "summary",
                "content": session["summary"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            session["auto_drive"] = False
            save_session(session)
            return _ui_state(session)

        tool_name = llm_response.tool_name
        params = llm_response.arguments
        capability = getattr(llm_response, "capability", None)
        # Legacy integrations and tests return tool-only response objects.
        if not isinstance(capability, str) or not capability.strip():
            capability = None
        if capability:
            resolution = resolve_capability(capability, preferences=session.get("tool_preferences"))
            if resolution.tool_name is None:
                session["action_history"].append({
                    "type": "chat", "content": f"No supported implementation is registered for capability **{capability}**.",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                session["status"] = "active"
                save_session(session)
                return _ui_state(session)
            if resolution.status != "installed":
                candidate = resolution.installable or (resolution.candidates[0] if resolution.candidates else None)
                if candidate is None:
                    session["action_history"].append({
                        "type": "chat", "content": f"Capability **{capability}** resolves to **{resolution.tool_name}**, which is installable but not healthy on this host. Install and verify it through the Tool Registry before execution.",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    session["status"] = "active"
                    save_session(session)
                    return _ui_state(session)
                # Auto-install, subject to confirmation: the resolver returned
                # the best installable implementation. We park an *install
                # proposal* in the same confirmation gate. Confirming installs
                # + verifies the tool and only then re-parks the execution
                # params — the LLM never touches a binary name.
                session["_pending_param_confirm"] = {
                    "action_kind": "install",
                    "tool_name": candidate.tool_name,
                    "capability": capability,
                    "arguments": params,
                    "install_command": candidate.install_command,
                    "verification_command": candidate.verification_command,
                    "requirements": candidate.requirements,
                }
                session["status"] = "awaiting_params"
                session["auto_drive"] = False
                session["action_history"].append({
                    "type": "chat",
                    "content": (
                        f"To perform **{capability}** I need the tool **{candidate.tool_name}**, "
                        f"which is not installed on this host. I'll install it "
                        f"(`{candidate.install_command}`) and verify it. "
                        f"Review the install card, then click **Execute** to install and "
                        f"continue, or **Cancel** to skip."
                    ),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                save_session(session)
                return _ui_state(session)
            tool_name = resolution.tool_name

        # A session runs at most one sandbox job at a time. If a scan is still
        # in flight (e.g. the user sends a new message mid-scan), don't kick a
        # concurrent job — store the context and let the auto-drive worker
        # continue the workflow once the running job is terminal.
        if any(a.get("outcome") == "executing" for a in session.get("action_history", [])):
            session["status"] = "active"
            session["auto_drive"] = True
            save_session(session)
            return _ui_state(session)

        try:
            tool = get_tool(tool_name)
        except ToolRegistryError as e:
            session["action_history"].append({
                "type": "error",
                "message": f"Unknown tool '{tool_name}': {e}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            session["status"] = "active"
            session["auto_drive"] = False
            save_session(session)
            return _ui_state(session)

        _fill_defaults(tool, params)

        # Deterministic param-confirmation gate: the LLM proposes an action, but
        # it never executes it. The params (with defaults already merged) are
        # parked so the UI can show the user "use these defaults or override
        # them" and only run after an explicit confirm.
        session["_pending_param_confirm"] = {"tool_name": tool_name, "params": params, "capability": capability}
        session["status"] = "awaiting_params"
        session["auto_drive"] = False
        session["action_history"].append({
            "type": "chat",
            "content": (
                f"Proposed capability: **{capability or tool_name}** on {params.get('target', '?')} "
                f"(resolved to **{tool_name}**).\n\n"
                "Review the params in the card — keep the defaults or override "
                "them, then click **Execute**. Click **Cancel** to skip this action."
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        save_session(session)
        return _ui_state(session)


def _run_confirmed_action(session: dict, tool_name: str, params: dict, capability: str | None = None) -> dict:
    """Execute a user-confirmed tool call through the shared pipeline.

    Runs the same path the Sandbox tab uses: scope validation → build_command →
    approval gate (active_scan/exploit) → async sandbox job. Mutates the session
    in place and returns the UI state. ``capability`` is the investigator-level
    need the resolved tool satisfies (recorded on the action for the analyst).
    """
    try:
        tool = get_tool(tool_name)
    except ToolRegistryError as e:
        session["action_history"].append({
            "type": "error",
            "message": f"Unknown tool '{tool_name}': {e}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        session["status"] = "active"
        session["auto_drive"] = False
        return _ui_state(session)

    _fill_defaults(tool, params)

    # One sandbox job at a time: never kick a second job while one is running.
    if any(a.get("outcome") == "executing" for a in session.get("action_history", [])):
        session["status"] = "active"
        session["auto_drive"] = True
        return _ui_state(session)

    engagement_id = session["engagement_id"]
    result = execute_action(engagement_id, tool_name, params)

    if "error" in result:
        action_record = {
            "type": "action",
            "tool_name": tool_name,
            "capability": capability if isinstance(capability, str) and capability else None,
            "params": params,
            "target": params.get("target", ""),
            "outcome": "denied",
            "reason": result["error"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        session["action_history"].append(action_record)
        session["pending_or_denied"].append(action_record)
        session["status"] = "active"
        session["auto_drive"] = True
        return _ui_state(session)

    if result.get("status") == "pending_approval":
        approval_id = result["approval_id"]
        action_record = {
            "type": "action",
            "tool_name": tool_name,
            "capability": capability if isinstance(capability, str) and capability else None,
            "params": params,
            "target": params.get("target", ""),
            "outcome": "pending_approval",
            "approval_id": approval_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        session["action_history"].append(action_record)
        session["pending_or_denied"].append(action_record)
        session["status"] = "pending_approval"
        session["_pending_approval_id"] = approval_id
        session["auto_drive"] = True
        return _ui_state(session)

    job_id = result["job_id"]
    action_record = {
        "type": "action",
        "tool_name": tool_name,
        "capability": capability if isinstance(capability, str) and capability else None,
        "params": params,
        "target": params.get("target", ""),
        "outcome": "executing",
        "job_id": job_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    session["action_history"].append(action_record)
    # Non-blocking: the job runs in the sandbox in a background thread.
    # The auto-drive worker polls the job, records findings when it is
    # terminal, and then continues the workflow. This keeps the request fast
    # and lets the UI show live "RUNNING" progress instead of blocking for
    # the full scan duration.
    session["status"] = "active"
    session["auto_drive"] = True
    return _ui_state(session)


def confirm_params(session_id: str, params: dict) -> dict:
    """User accepted (and possibly overrode) the parked params. Execute now.

    Two kinds of parked confirmation are possible:
      - a normal tool execution (action_kind omitted / "execute"), or
      - an automatic tool install (action_kind == "install"), which installs
        and verifies the resolver-selected implementation and then re-parks
        the execution params for a second confirmation.
    """
    with _session_lock(session_id):
        session = load_session(session_id)
        if session is None:
            return {"error": f"Session '{session_id}' not found"}

        pending = session.get("_pending_param_confirm")
        if not pending:
            return _ui_state(session)

        action_kind = pending.get("action_kind", "execute")

        if action_kind == "install":
            from tool_registry.installer import ensure_tool
            tool_name = pending["tool_name"]
            capability = pending.get("capability")
            result = ensure_tool(tool_name)
            session["_pending_param_confirm"] = None

            if result.get("status") != "installed":
                session["action_history"].append({
                    "type": "chat",
                    "content": (
                        f"Installation of **{tool_name}** for capability **{capability}** "
                        f"failed: {result.get('output', 'unknown error')} — no action was executed."
                    ),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                session["status"] = "active"
                session["auto_drive"] = False
                save_session(session)
                return _ui_state(session)

            # Installed + verified. Re-resolve (now installed) and park the
            # actual execution params for the usual confirmation gate.
            session["action_history"].append({
                "type": "chat",
                "content": f"Installed and verified **{tool_name}** for capability **{capability}**. Proposing the scan parameters now.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            resolution = resolve_capability(capability, preferences=session.get("tool_preferences"))
            exec_tool = resolution.tool_name if resolution.status == "installed" else tool_name
            exec_params = dict(pending.get("arguments") or {})
            try:
                tool = get_tool(exec_tool)
            except ToolRegistryError:
                tool = None
            _fill_defaults(tool, exec_params) if tool else None
            session["_pending_param_confirm"] = {
                "tool_name": exec_tool,
                "params": exec_params,
                "capability": capability,
            }
            session["status"] = "awaiting_params"
            session["auto_drive"] = False
            save_session(session)
            return _ui_state(session)

        tool_name = pending["tool_name"]
        session["_pending_param_confirm"] = None

        # Re-merge registry defaults so any blank field the user left falls
        # back to the tool default, matching build_command() semantics.
        try:
            tool = get_tool(tool_name)
        except ToolRegistryError:
            tool = None
        merged = {**(tool.get("defaults", {}) if tool else {}), **params}

        result = _run_confirmed_action(session, tool_name, merged, pending.get("capability"))
        save_session(session)
        return result


def cancel_params(session_id: str) -> dict:
    """User dismissed the parked action. Nothing executes."""
    with _session_lock(session_id):
        session = load_session(session_id)
        if session is None:
            return {"error": f"Session '{session_id}' not found"}

        pending = session.get("_pending_param_confirm")
        if pending:
            session["action_history"].append({
                "type": "chat",
                "content": (
                    f"Cancelled **{pending['tool_name']}** — nothing was executed. "
                    f"Tell me what you'd like to do next."
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        session["_pending_param_confirm"] = None
        session["status"] = "active"
        session["auto_drive"] = False
        save_session(session)
        return _ui_state(session)


def _fill_defaults(tool: dict, params: dict):
    defaults = tool.get("defaults", {})
    for key, val in defaults.items():
        if key not in params or not params.get(key):
            params[key] = val


def _record_job_findings(session: dict, action_record: dict, job_id: str):
    job = SandboxExecutor.get_result(job_id)
    if job is None:
        return
    status = job.get("status")
    if status not in ("completed", "error", "timeout"):
        return

    action_record["outcome"] = status
    action_record["exit_code"] = job.get("exit_code")

    findings = job.get("findings")
    tool_name = action_record.get("tool_name", "unknown")
    if findings and isinstance(findings, dict):
        for f in findings.get("findings", []):
            f["_tool"] = tool_name
            f["_job_id"] = job_id
            session["findings_so_far"].append(f)

    if tool_name not in session["tools_already_run"]:
        session["tools_already_run"].append(tool_name)


def _resolve_pending(session: dict):
    approval_id = session.get("_pending_approval_id")
    if not approval_id:
        return

    record = get_approval(approval_id)
    if record is None:
        session["_pending_approval_id"] = None
        return

    status = record["status"]

    if status == "approved":
        job_id = record.get("result_job_id")
        if not job_id:
            return
        # Non-blocking: only resolve once the approved job is actually terminal.
        job = SandboxExecutor.get_result(job_id)
        if job is None or job.get("status") in ("queued", "running"):
            return

        pending_items = [
            a for a in session["pending_or_denied"]
            if a.get("approval_id") == approval_id
        ]
        for item in pending_items:
            item["outcome"] = "approved"
            item["job_id"] = job_id

        action_items = [
            a for a in session["action_history"]
            if a.get("approval_id") == approval_id
        ]
        for item in action_items:
            item["outcome"] = "approved"
            item["job_id"] = job_id

        _record_job_findings(session, action_items[0] if action_items else {}, job_id)
        session["_pending_approval_id"] = None

    elif status in ("denied", "expired"):
        for item in session["pending_or_denied"]:
            if item.get("approval_id") == approval_id:
                item["outcome"] = status
                item["reason"] = record.get("deny_reason", f"Action was {status}")
        for item in session["action_history"]:
            if item.get("approval_id") == approval_id:
                item["outcome"] = status
        session["_pending_approval_id"] = None


def _has_active_pending(session: dict) -> bool:
    for item in session.get("pending_or_denied", []):
        if item.get("outcome") == "pending_approval":
            return True
    return False


def _poll_job_and_record_findings(session: dict, action_record: dict, job_id: str) -> bool:
    """Single non-blocking poll of a sandbox job.

    Returns True once the job reached a terminal state (findings recorded);
    False if it is still queued/running. Never blocks — the caller (auto-drive
    worker) re-polls on later ticks.
    """
    job = SandboxExecutor.get_result(job_id)
    if job is None:
        # The executor only tracks in-memory jobs, so a missing record means
        # the executor restarted mid-run. Surface it instead of hanging forever.
        action_record["outcome"] = "error"
        action_record["exit_code"] = -1
        action_record["reason"] = "Job state lost (executor restarted?)"
        return True

    status = job.get("status")
    if status not in ("completed", "error", "timeout"):
        return False

    _record_job_findings(session, action_record, job_id)
    return True


def resolve_pending_approvals(session_id: str) -> dict | None:
    session = load_session(session_id)
    if session is None:
        return None
    _resolve_pending(session)
    save_session(session)
    return _ui_state(session)


def _auto_drive_loop():
    import time
    while True:
        time.sleep(_AUTO_CONTINUE_INTERVAL)
        try:
            sessions = list_sessions()
        except Exception:
            continue

        for s in sessions:
            sid = s.get("session_id")
            if not sid:
                continue
            try:
                session = load_session(sid)
            except Exception:
                continue
            if not session:
                continue

            status = session.get("status")

            if status == "active":
                hist = session.get("action_history", [])
                actions = [a for a in hist if a.get("type") == "action"]
                if not actions:
                    continue
                executing = [a for a in actions if a.get("outcome") == "executing"]
                if executing:
                    # Resolve every in-flight action whose job is now terminal —
                    # even when auto_drive is off (e.g. a chat reply landed
                    # mid-scan), so actions never stay stuck on "executing".
                    # Do NOT continue the workflow while any job is still
                    # running, so a session never kicks a second scan
                    # concurrently.
                    progressed = False
                    still_running = False
                    for a in executing:
                        job_id = a.get("job_id", "")
                        if not job_id:
                            a["outcome"] = "error"
                            a["reason"] = "Missing job id"
                            progressed = True
                            continue
                        try:
                            terminal = _poll_job_and_record_findings(session, a, job_id)
                        except Exception:
                            terminal = False
                        if terminal:
                            progressed = True
                        else:
                            still_running = True
                    if not progressed:
                        continue
                    save_session(session)
                    if still_running or not session.get("auto_drive"):
                        continue
                else:
                    if not session.get("auto_drive"):
                        continue
                    if actions[-1].get("outcome") not in ("completed", "error", "timeout", "denied"):
                        continue
                try:
                    orchestrator_step(sid)
                except Exception:
                    pass

            elif status == "pending_approval":
                approval_id = session.get("_pending_approval_id")
                if not approval_id:
                    continue
                try:
                    record = get_approval(approval_id)
                except Exception:
                    continue
                if record is None or record["status"] not in ("approved", "denied", "expired"):
                    continue
                if record["status"] == "approved":
                    job_id = record.get("result_job_id")
                    if not job_id:
                        continue
                    try:
                        job = SandboxExecutor.get_result(job_id)
                    except Exception:
                        job = None
                    if job is None or job.get("status") in ("queued", "running"):
                        continue
                try:
                    orchestrator_step(sid)
                except Exception:
                    pass


def start_auto_continue_worker() -> threading.Thread:
    thread = threading.Thread(target=_auto_drive_loop, daemon=True, name="redteam-drive")
    thread.start()
    return thread


def _ui_state(session: dict) -> dict:
    return {
        "session_id": session.get("session_id"),
        "engagement_id": session.get("engagement_id"),
        "goal": session.get("goal", ""),
        "status": session.get("status", "active"),
        "summary": session.get("summary"),
        "findings_so_far": session.get("findings_so_far", []),
        "tools_already_run": session.get("tools_already_run", []),
        "action_history": session.get("action_history", []),
        "pending_or_denied": [
            a for a in session.get("pending_or_denied", [])
            if a.get("outcome") in ("pending_approval",)
        ],
        "pending_param_confirm": session.get("_pending_param_confirm"),
        "investigation": session.get("investigation"),
        "created_at": session.get("created_at"),
        "updated_at": session.get("updated_at"),
    }
