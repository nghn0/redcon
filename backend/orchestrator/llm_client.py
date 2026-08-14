import json
import os
import httpx
from tool_registry.registry import get_all_tools
from .tool_schemas import generate_capability_schemas, get_system_prompt
from .investigate import knowledge

LLM_API_BASE = os.environ.get("LLM_API_BASE", "http://127.0.0.1:11434/v1")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "qwen2.5-coder:7b")

MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "2048"))
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "120"))


def check_llm_health() -> dict:
    try:
        resp = httpx.get(f"{LLM_API_BASE}/models", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            models = [m["id"] for m in data.get("data", [])]
            available = LLM_MODEL in models
            return {"connected": True, "model": LLM_MODEL, "model_available": available, "models": models}
        return {"connected": False, "error": f"HTTP {resp.status_code}"}
    except httpx.ConnectError:
        return {"connected": False, "error": f"Could not connect to {LLM_API_BASE}"}
    except Exception as e:
        return {"connected": False, "error": str(e)}


class LLMResponse:
    def __init__(self, is_tool_call: bool, tool_name: str = None,
                 arguments: dict = None, content: str = None, finish: bool = False,
                 intent: str = None, capability: str = None):
        self.is_tool_call = is_tool_call
        self.tool_name = tool_name
        self.arguments = arguments or {}
        self.content = content or ""
        self.finish = finish
        self.intent = intent or ("execute" if is_tool_call else "conversation")
        self.capability = capability


def _parse_tool_call(content: str) -> tuple[str, dict] | None:
    cleaned = content.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        cleaned = "\n".join(
            line for line in lines
            if not line.startswith("```")
        ).strip()

    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict) and "name" in obj:
            args = obj.get("arguments") or obj.get("parameters") or {}
            if isinstance(args, str):
                args = json.loads(args)
            return obj["name"], args
    except (json.JSONDecodeError, TypeError):
        pass

    try:
        obj = json.loads("{" + cleaned + "}")
        if isinstance(obj, dict) and "name" in obj:
            args = obj.get("arguments") or obj.get("parameters") or {}
            if isinstance(args, str):
                args = json.loads(args)
            return obj["name"], args
    except (json.JSONDecodeError, TypeError):
        pass

    import re
    m = re.search(r'["\']name["\']\s*:\s*["\'](\w+)["\']', cleaned)
    if m:
        tool_name = m.group(1)
        args = {}
        m2 = re.search(r'["\']arguments["\']\s*:\s*(\{|\[)', cleaned)
        if m2:
            try:
                start = m2.start(1)
                depth = 0
                i = start
                while i < len(cleaned):
                    if cleaned[i] in "{[":
                        depth += 1
                    elif cleaned[i] in "}]":
                        depth -= 1
                        if depth == 0:
                            args_str = cleaned[start:i+1]
                            args = json.loads(args_str)
                            break
                    i += 1
            except (json.JSONDecodeError, IndexError):
                pass
        return tool_name, args

    return None


def _strip_fences(content: str) -> str:
    cleaned = content.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        cleaned = "\n".join(
            line for line in lines
            if not line.startswith("```")
        ).strip()
    return cleaned


def _parse_envelope(content: str) -> dict | None:
    """Parse the model's JSON envelope: {"intent", "reply", "action"}.

    Returns None when the content is not an intent envelope.
    """
    cleaned = _strip_fences(content)
    if not cleaned.startswith("{"):
        return None

    for candidate in (cleaned,):
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict) and "intent" in obj:
                return obj
        except (json.JSONDecodeError, TypeError):
            pass

    start = cleaned.find("{")
    if start != -1:
        depth = 0
        for i in range(start, len(cleaned)):
            ch = cleaned[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(cleaned[start:i + 1])
                        if isinstance(obj, dict) and "intent" in obj:
                            return obj
                    except (json.JSONDecodeError, TypeError):
                        pass
                    break
    return None


_REGISTERED_TOOL_NAMES = [t["name"] for t in get_all_tools()]


def _resolve_tool_name(raw) -> str | None:
    """Map whatever the model put in the envelope 'name' to a registered tool.

    qwen2.5-coder sometimes echoes the full tool description (e.g. "nmap Port
    and service scanner (passive - ...)") instead of just the tool name, so
    match on the leading tool name as well as exact matches.
    """
    if not raw:
        return None
    s = str(raw).strip()
    if s == "finish_engagement":
        return s
    if s in _REGISTERED_TOOL_NAMES:
        return s
    for name in sorted(_REGISTERED_TOOL_NAMES, key=len, reverse=True):
        if s.startswith(name):
            return name
    return None


def _normalize_intent(raw) -> str | None:
    if not raw:
        return None
    r = str(raw).strip().lower()
    if r in ("execute", "run", "scan", "test", "action", "do"):
        return "execute"
    if r in ("plan", "explain", "approach", "howto", "proposal", "strategy"):
        return "plan"
    if r in ("conversation", "chat", "chatting", "question", "info", "report", "general", "converse"):
        return "conversation"
    return None


def _envelope_to_response(env: dict) -> LLMResponse | None:
    intent = _normalize_intent(env.get("intent"))
    if intent is None:
        return None
    reply = env.get("reply") or ""
    action = env.get("action")

    if intent == "execute" and isinstance(action, dict):
        capability = action.get("capability")
        if capability:
            args = action.get("arguments") or action.get("parameters") or {}
            return LLMResponse(is_tool_call=True, arguments=args if isinstance(args, dict) else {},
                               content=reply, intent="execute", capability=str(capability))
        tool_name = _resolve_tool_name(action.get("name"))
        if tool_name is None:
            return LLMResponse(
                is_tool_call=False,
                content=reply or "I couldn't map that action to an available tool, so nothing was executed.",
                intent="execute",
            )
        args = action.get("arguments") or action.get("parameters") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {}
        if not isinstance(args, dict):
            args = {}
        if tool_name == "finish_engagement":
            return LLMResponse(
                is_tool_call=False,
                content=args.get("summary", reply or "Engagement complete."),
                finish=True,
                intent="execute",
            )
        return LLMResponse(
            is_tool_call=True,
            tool_name=tool_name,
            arguments=args,
            content=reply,
            intent="execute",
        )

    if not reply:
        if intent == "plan":
            reply = "Here is my proposed approach. Tell me to proceed and I'll run it."
        else:
            reply = "Got it."
    return LLMResponse(is_tool_call=False, content=reply, intent=intent)


def _complete(system_prompt: str, compact: dict, user_text: str, schemas: list) -> LLMResponse:
    """Single LLM call; parses the model output into an LLMResponse."""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Engagement state:\n{json.dumps(compact, indent=2)}{user_text}\n\nRespond according to the selected interaction intent."},
    ]

    body = {
        "model": LLM_MODEL,
        "messages": messages,
        "max_tokens": MAX_TOKENS,
        "temperature": 0.2,
    }
    if schemas:
        body["tools"] = schemas
        body["tool_choice"] = "auto"

    try:
        resp = httpx.post(
            f"{LLM_API_BASE}/chat/completions",
            json=body,
            timeout=LLM_TIMEOUT,
            headers={"Authorization": f"Bearer {LLM_API_KEY}"} if LLM_API_KEY else {},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return LLMResponse(is_tool_call=False, content=f"LLM API error: {e}")

    try:
        choice = data["choices"][0]
        message = choice.get("message", {})
        finish_reason = choice.get("finish_reason", "stop")

        if finish_reason == "tool_calls" and message.get("tool_calls"):
            tc = message["tool_calls"][0]
            tool_name = tc["function"]["name"]
            try:
                arguments = json.loads(tc["function"]["arguments"])
            except (json.JSONDecodeError, TypeError):
                arguments = {}
            if tool_name == "request_capability":
                return LLMResponse(is_tool_call=True, capability=arguments.get("capability"),
                                   arguments=arguments.get("arguments") or {})
            return LLMResponse(is_tool_call=True, tool_name=tool_name, arguments=arguments)

        content = message.get("content", "")
        if content:
            env = _parse_envelope(content)
            if env:
                response = _envelope_to_response(env)
                if response is not None:
                    return response

            parsed = _parse_tool_call(content)
            if parsed:
                tool_name, arguments = parsed
                if tool_name == "finish_engagement":
                    return LLMResponse(
                        is_tool_call=False,
                        content=arguments.get("summary", "Engagement complete."),
                        finish=True,
                        intent="execute",
                    )
                return LLMResponse(is_tool_call=True, tool_name=tool_name, arguments=arguments)

        if content:
            return LLMResponse(is_tool_call=False, content=content)

        return LLMResponse(is_tool_call=False, content="No response from LLM.")

    except (KeyError, IndexError, TypeError) as e:
        return LLMResponse(is_tool_call=False, content=f"Failed to parse LLM response: {e}")


def _last_assistant_text(state: dict) -> str | None:
    conv = _build_conversation(state)
    for m in reversed(conv):
        if m["role"] == "assistant" and m["text"].strip():
            return m["text"].strip()
    return None


def decide(state: dict, user_message: str | None = None,
           interaction_intent: str = "execution") -> LLMResponse:
    """Ask the LLM to respond within an already-classified interaction mode."""
    execution = interaction_intent == "execution"
    schemas = generate_capability_schemas() if execution else []
    system_prompt = get_system_prompt(state, interaction_intent=interaction_intent)
    compact = _build_compact_state(state, include_execution_context=execution)

    user_text = ""
    if user_message:
        user_text = f"\n\nUser message:\n{user_message}"

    response = _complete(system_prompt, compact, user_text, schemas)

    # Guard against output degeneration: small coder models sometimes respond to
    # a follow-up question by repeating their previous reply verbatim (especially
    # after a safety refusal). That is a broken reply, so retry once with a
    # corrective note before surfacing it to the user.
    last_assistant = _last_assistant_text(state)
    if (
        last_assistant
        and not response.is_tool_call
        and not response.finish
        and response.content
        and not response.content.startswith("LLM API error")
        and not response.content.startswith("Failed to parse")
        and response.content.strip() == last_assistant
    ):
        note = (
            "\n\nNOTE: The user's message is a follow-up question about your last reply "
            f"(\"{last_assistant}\"). Answer it directly and do NOT repeat your last reply. "
            "If your last reply was a refusal, explain the specific reason behind it "
            "(for example, the target is not in the authorized engagement scope). "
            "Output the JSON envelope."
        )
        response = _complete(system_prompt, compact, user_text + note, schemas)

    # If the model STILL repeats the previous reply after a corrective retry,
    # never surface a verbatim duplicate. Replace it with a short, neutral follow-up
    # acknowledging the last result so the UI moves forward instead of echoing.
    if (
        last_assistant
        and not response.is_tool_call
        and not response.finish
        and response.content
        and not response.content.startswith("LLM API error")
        and not response.content.startswith("Failed to parse")
        and response.content.strip() == last_assistant
    ):
        response = LLMResponse(
            is_tool_call=False,
            content=(
                "Understood. Review the results above and tell me what you'd like to "
                "do next."
            ),
            intent="conversation",
        )

    # A second boundary at the LLM adapter protects callers other than the
    # engine from accidental action generation in conversation/planning mode.
    if not execution and (response.is_tool_call or response.finish):
        return LLMResponse(
            is_tool_call=False,
            content=response.content or "I can explain or plan that. Tell me explicitly when you want me to run it.",
            intent=interaction_intent,
        )
    response.intent = interaction_intent if not execution else response.intent
    return response


def _capability_inventory() -> list[dict]:
    """Factual catalog of registered capabilities and the tools that perform
    them, with their current execution status.

    Included in the engagement state in every interaction mode so the model can
    truthfully answer questions such as "what tools are installed?" or "what
    can you use?" without guessing. Planning conversation only gets these facts;
    the ranked candidate/action menu stays execution-context.
    """
    from tool_registry import capabilities as resolver
    from tool_registry import capability_catalog as catalog
    from tool_registry.registry import get_all_tools

    envs = {t["name"]: t.get("execution_environment", "") for t in get_all_tools()}
    inventory = []
    for cap in catalog.capability_names():
        resolution = resolver.resolve(cap)
        inventory.append({
            "capability": cap,
            "description": catalog.describe(cap),
            "phase": catalog.default_phase(cap),
            "risk": catalog.default_risk_tier(cap),
            "tools": [
                {
                    "name": tc.tool_name,
                    "environment": envs.get(tc.tool_name, ""),
                    "status": tc.status,  # installed | installable | unavailable
                }
                for tc in resolution.candidates
            ],
        })
    return inventory


def _build_compact_state(state: dict, include_execution_context: bool = True) -> dict:
    compact = {
        "engagement_id": state.get("engagement_id", ""),
        "goal": state.get("goal", ""),
        "conversation": _build_conversation(state),
        "findings_so_far": _summarize_findings(state.get("findings_so_far", [])),
        "tools_already_run": state.get("tools_already_run", []),
        "available_capabilities": _capability_inventory(),
        "pending_or_denied": [
            {
                "tool_name": a.get("tool_name"),
                "target": a.get("target"),
                "outcome": a.get("outcome"),
                "reason": a.get("reason", ""),
            }
            for a in state.get("pending_or_denied", [])
            if a.get("outcome") in ("denied", "expired")
        ],
    }

    if include_execution_context:
        # Investigation blackboard and its candidate-action menu are execution
        # context only. Keeping them out of planning prompts prevents tool
        # selection from biasing a methodology discussion.
        board = state.get("investigation")
        if isinstance(board, dict):
            compact["investigation"] = _summarize_investigation(board)
            compact["candidate_actions"] = board.get("action_scores", [])
            g = knowledge.summarize_gaps(board, goal=compact.get("goal", ""))
            if g:
                compact["open_questions"] = g

    n = len(compact.get("findings_so_far", []))
    if n > 50:
        compact["findings_so_far"] = compact["findings_so_far"][:50]
        compact["findings_truncated"] = n
    return compact


def _summarize_investigation(board: dict) -> dict:
    """A bounded, plain summarization of the blackboard for the LLM context."""
    assets = []
    for a in board.get("assets", []):
        assets.append({
            "target": a.get("target"),
            "type": a.get("type"),
            "ports": a.get("ports", [])[:12],
            "services": a.get("services", [])[:8],
            "paths": a.get("paths", [])[:8],
        })

    hypotheses = [
        {"hypothesis": h.get("hypothesis"), "status": h.get("status"),
         "confidence": h.get("confidence")}
        for h in board.get("hypotheses", [])[:8]
    ]
    open_unknowns = [
        {"question": u.get("question"), "importance": u.get("importance")}
        for u in board.get("unknowns", [])
        if u.get("status") == "open"
    ][:6]
    vulns = [
        {"name": v.get("name"), "severity": v.get("severity"),
         "target": v.get("target"), "confidence": v.get("confidence")}
        for v in board.get("potential_vulnerabilities", [])[:8]
    ]

    return {
        "objective": board.get("objective", ""),
        "phase": board.get("phase"),
        "phases_visited": board.get("phases_visited", []),
        "confidence": board.get("confidence", 0.0),
        "next_objective": board.get("next_objective", ""),
        "documented_facts": [f.get("fact") for f in board.get("known_facts", [])[:15]],
        "hypotheses": hypotheses,
        "open_unknowns": open_unknowns,
        "assets": assets,
        "interesting_assets": board.get("interesting_assets", []),
        "interesting_ports": board.get("interesting_ports", []),
        "interesting_services": board.get("interesting_services", []),
        "interesting_paths": board.get("interesting_paths", []),
        "potential_vulnerabilities": vulns,
        "completed_actions": board.get("completed_actions", []),
        "failed_actions": board.get("failed_actions", []),
    }


def _build_conversation(state: dict, limit: int = 12) -> list[dict]:
    """Recent exchange history so the model can answer follow-up questions."""
    conv = []
    for e in state.get("action_history", [])[-limit:]:
        t = e.get("type")
        if t in ("user", "chat", "summary"):
            conv.append({
                "role": "user" if t == "user" else "assistant",
                "text": e.get("content", ""),
            })
        elif t == "action":
            conv.append({
                "role": "assistant",
                "text": (
                    f"ran {e.get('tool_name')} on {e.get('target', '?')}: "
                    f"{e.get('outcome', '')}"
                ),
            })
    return conv


def _summarize_findings(findings: list) -> list:
    if not findings:
        return []
    summary = []
    for f in findings:
        ftype = f.get("type", "unknown")
        detail = f.get("detail", {})
        s = {"type": ftype, "tool": f.get("_tool", "unknown")}
        if ftype == "port_open":
            s["port"] = detail.get("port")
            s["service"] = detail.get("service")
            s["version"] = detail.get("version")
        elif ftype == "port_filtered":
            s["port"] = detail.get("port")
            s["service"] = detail.get("service")
        elif ftype == "vulnerability":
            s["name"] = detail.get("name", "")
            s["severity"] = detail.get("severity", "")
            s["matched"] = detail.get("matched", "")
        elif ftype == "discovered_path":
            s["path"] = detail.get("path")
            s["status"] = detail.get("status")
        elif ftype == "subdomain":
            s["subdomain"] = detail.get("subdomain")
        elif ftype == "nikto_finding":
            s["path"] = detail.get("path")
            s["message"] = detail.get("message")
        elif ftype == "sql_injection":
            s["parameter"] = detail.get("parameter")
            s["method"] = detail.get("method")
        elif ftype == "credential_found":
            s["host"] = detail.get("host")
            s["port"] = detail.get("port")
            s["service"] = detail.get("service")
            s["login"] = detail.get("login")
        else:
            s["detail"] = detail
        summary.append(s)
    return summary
