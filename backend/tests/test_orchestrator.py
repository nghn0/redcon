import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from orchestrator.engine import orchestrator_step, confirm_params
from orchestrator.state import create_session, load_session, SESSIONS_DIR
from orchestrator.tool_schemas import generate_tool_schemas, get_system_prompt
from orchestrator.llm_client import (
    LLMResponse,
    _parse_tool_call,
    _build_compact_state,
    _parse_envelope,
    _envelope_to_response,
    decide,
)
from orchestrator.intent import CONVERSATION, EXECUTION, PLAN, classify_intent

TEST_SESSIONS_DIR = Path(__file__).parent.parent / "data" / "test_sessions"


def _use_test_path():
    import orchestrator.state as state_mod
    state_mod.SESSIONS_DIR = TEST_SESSIONS_DIR


def _cleanup():
    import shutil
    if TEST_SESSIONS_DIR.exists():
        shutil.rmtree(TEST_SESSIONS_DIR)


def _fake_llm_response(tool_name: str = None, arguments: dict = None, content: str = None, finish: bool = False):
    """Create a mock LLM response. If tool_name given, pretends to return a tool call."""
    mock = MagicMock()
    mock.is_tool_call = tool_name is not None
    mock.tool_name = tool_name
    mock.arguments = arguments or {}
    mock.content = content or ""
    mock.finish = finish
    return mock


@pytest.fixture(autouse=True)
def setup():
    _use_test_path()
    _cleanup()
    yield
    _cleanup()


class TestToolSchemas:
    def test_generate_tool_schemas_returns_all_7_plus_finish(self):
        schemas = generate_tool_schemas()
        assert len(schemas) == 8
        names = [s["function"]["name"] for s in schemas]
        assert "nmap" in names
        assert "nikto" in names
        assert "finish_engagement" in names

    def test_tool_schema_has_description_and_params(self):
        schemas = generate_tool_schemas()
        nmap = next(s for s in schemas if s["function"]["name"] == "nmap")
        fn = nmap["function"]
        assert "port" in fn["description"].lower()
        assert "target" in fn["parameters"]["properties"]
        assert "ports" in fn["parameters"]["properties"]
        assert "target" in fn["parameters"]["required"]

    def test_system_prompt_guides_conversation_vs_testing(self):
        prompt = get_system_prompt({})
        assert "CONVERSATION" in prompt
        assert "SECURITY TESTING" in prompt
        assert "finish" in prompt.lower()
        assert "approval" in prompt.lower()
        assert "scope" in prompt.lower()

    def test_system_prompt_does_not_hardcode_tool_workflow(self):
        prompt = get_system_prompt({})
        for tool in ("nmap", "nikto", "gobuster", "sqlmap", "hydra", "subfinder", "nuclei"):
            assert tool not in prompt.lower(), f"Prompt should not hardcode tool '{tool}'"


class TestLLMClient:
    def test_parse_tool_call_json(self):
        result = _parse_tool_call('{"name": "nmap", "arguments": {"target": "example.com", "ports": "80"}}')
        assert result is not None
        name, args = result
        assert name == "nmap"
        assert args["target"] == "example.com"

    def test_parse_tool_call_with_code_block(self):
        result = _parse_tool_call('```json\n{"name": "nmap", "arguments": {"target": "test.local"}}\n```')
        assert result is not None
        name, args = result
        assert name == "nmap"
        assert args["target"] == "test.local"

    def test_parse_tool_call_finish(self):
        result = _parse_tool_call('{"name": "finish_engagement", "arguments": {"summary": "done"}}')
        assert result is not None
        name, args = result
        assert name == "finish_engagement"
        assert args["summary"] == "done"

    def test_parse_tool_call_returns_none_for_plain_text(self):
        result = _parse_tool_call("I have completed the scan. Here is a summary of findings.")
        assert result is None

    def test_compact_state_excludes_raw_stdout(self):
        state = {
            "findings_so_far": [
                {"type": "port_open", "detail": {"port": 80, "service": "http"}, "_tool": "nmap", "_job_id": "sbox-001"},
                {"type": "vulnerability", "detail": {"name": "XSS", "severity": "high"}, "_tool": "nuclei"},
            ],
            "tools_already_run": ["nmap", "nuclei"],
            "pending_or_denied": [],
        }
        compact = _build_compact_state(state)
        assert "findings_so_far" in compact
        assert len(compact["findings_so_far"]) == 2
        assert compact["findings_so_far"][0]["type"] == "port_open"
        raw_keys = {"stdout", "stderr", "raw", "exit_code", "command"}
        for f in compact["findings_so_far"]:
            for key in raw_keys:
                assert key not in f, f"Compact state should not contain raw '{key}'"

    def test_compact_state_size_does_not_balloon(self):
        state = {
            "findings_so_far": [
                {"type": "port_open", "detail": {"port": p}, "_tool": "nmap"}
                for p in range(50)
            ],
            "tools_already_run": ["nmap"],
            "pending_or_denied": [],
        }
        compact = _build_compact_state(state)
        assert compact["findings_so_far"][0]["type"] == "port_open"
        assert compact["findings_so_far"][0]["port"] is not None


class TestSessionState:
    def test_create_session(self):
        session = create_session("eng-001", "Test engagement")
        assert session["session_id"].startswith("orch-")
        assert session["engagement_id"] == "eng-001"
        assert session["goal"] == "Test engagement"
        assert session["status"] == "active"
        assert session["findings_so_far"] == []
        assert session["action_history"] == []

    def test_save_and_load_session(self):
        session = create_session("eng-002", "Persist test")
        session_id = session["session_id"]
        loaded = load_session(session_id)
        assert loaded is not None
        assert loaded["session_id"] == session_id
        assert loaded["engagement_id"] == "eng-002"

    def test_load_nonexistent_session(self):
        assert load_session("nonexistent") is None

    def test_session_id_never_collides_after_counter_reset(self):
        import orchestrator.state as state_mod
        s1 = create_session("eng-a", "goal a")
        # Simulate a server restart: the in-memory counter resets to 0. A new
        # session must still pick an id that does not overwrite s1 on disk.
        state_mod._session_counter = 0
        s2 = create_session("eng-b", "goal b")
        assert s1["session_id"] != s2["session_id"]
        assert load_session(s1["session_id"]) is not None
        assert load_session(s1["session_id"])["engagement_id"] == "eng-a"
        assert load_session(s2["session_id"])["engagement_id"] == "eng-b"


class TestOrchestratorEngine:
    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_passive_tool_requires_param_confirmation_then_executes(self, mock_exec, mock_llm):
        mock_llm.return_value = _fake_llm_response("nmap", {"target": "127.0.0.1", "ports": "80"})
        mock_exec.return_value = {"job_id": "sbox-test-001"}

        with patch("orchestrator.engine.SandboxExecutor.get_result") as mock_get:
            mock_get.return_value = {
                "status": "completed",
                "exit_code": 0,
                "findings": {
                    "tool": "nmap",
                    "findings": [{"type": "port_open", "detail": {"port": 80, "service": "http"}}],
                },
            }
            session = create_session("eng-test-1", "scan for open ports")
            # Kick-off: the proposed action is parked for param confirmation,
            # nothing executes until the user explicitly accepts the params.
            result = orchestrator_step(session["session_id"])

            assert result["status"] == "awaiting_params"
            assert result["pending_param_confirm"] is not None
            assert result["pending_param_confirm"]["tool_name"] == "nmap"
            assert not any(a.get("type") == "action" for a in result["action_history"])
            mock_exec.assert_not_called()

            # User accepts the (default) params → action executes non-blocking.
            accepted = confirm_params(session["session_id"], result["pending_param_confirm"]["params"])
            assert accepted["status"] == "active"
            assert accepted["action_history"][-1]["type"] == "action"
            assert accepted["action_history"][-1]["outcome"] == "executing"

            # Simulate the auto-drive tick that polls the sandbox job.
            from orchestrator.engine import _poll_job_and_record_findings
            from orchestrator.state import load_session
            session_data = load_session(session["session_id"])
            last = session_data["action_history"][-1]
            assert _poll_job_and_record_findings(session_data, last, "sbox-test-001") is True

            assert last["outcome"] == "completed"
            assert len(session_data["findings_so_far"]) == 1

    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_confirm_params_override_replaces_defaults(self, mock_exec, mock_llm):
        mock_llm.return_value = _fake_llm_response("nmap", {"target": "127.0.0.1", "ports": "80"})
        mock_exec.return_value = {"job_id": "sbox-custom-001"}

        session = create_session("eng-test-16", "scan")
        result = orchestrator_step(session["session_id"])
        assert result["status"] == "awaiting_params"

        # User overrides the parked param before executing.
        accepted = confirm_params(
            session["session_id"],
            {"target": "127.0.0.1", "ports": "443"},
        )
        assert accepted["action_history"][-1]["outcome"] == "executing"
        assert mock_exec.call_args.args[2]["ports"] == "443", "Overridden param must replace the default"

    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_cancel_params_runs_nothing(self, mock_exec, mock_llm):
        from orchestrator.engine import cancel_params
        mock_llm.return_value = _fake_llm_response("nikto", {"target": "127.0.0.1", "port": "80"})

        session = create_session("eng-test-17", "scan")
        result = orchestrator_step(session["session_id"])
        assert result["status"] == "awaiting_params"

        dismissed = cancel_params(session["session_id"])
        assert dismissed["status"] == "active"
        assert dismissed["pending_param_confirm"] is None
        mock_exec.assert_not_called()
        assert any(a.get("type") == "chat" and "Cancelled" in a.get("content", "") for a in dismissed["action_history"])

    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_executing_job_is_not_marked_timeout_prematurely(self, mock_exec, mock_llm):
        """The engine must not cap waiting at a fixed 600s — a job that is still
        running keeps outcome='executing' until the sandbox marks it terminal."""
        mock_llm.return_value = _fake_llm_response("nmap", {"target": "127.0.0.1", "ports": "80"})
        mock_exec.return_value = {"job_id": "sbox-slow-001"}

        with patch("orchestrator.engine.SandboxExecutor.get_result") as mock_get:
            mock_get.return_value = {"status": "running", "exit_code": None, "findings": None}
            session = create_session("eng-test-14", "scan")
            orchestrator_step(session["session_id"])
            result = confirm_params(session["session_id"], {"target": "127.0.0.1", "ports": "80"})
            assert result["action_history"][-1]["outcome"] == "executing"

            from orchestrator.engine import _poll_job_and_record_findings
            from orchestrator.state import load_session
            session_data = load_session(session["session_id"])
            last = session_data["action_history"][-1]
            assert _poll_job_and_record_findings(session_data, last, "sbox-slow-001") is False
            assert last["outcome"] == "executing"

            mock_get.return_value = {"status": "completed", "exit_code": 0, "findings": None}
            assert _poll_job_and_record_findings(session_data, last, "sbox-slow-001") is True
            assert last["outcome"] == "completed"

    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_active_scan_returns_pending_approval(self, mock_exec, mock_llm):
        mock_llm.return_value = _fake_llm_response("nikto", {"target": "127.0.0.1", "port": "80"})
        mock_exec.return_value = {
            "status": "pending_approval",
            "approval_id": "apr-test-001",
        }

        session = create_session("eng-test-2", "check web server")
        orchestrator_step(session["session_id"])
        result = confirm_params(session["session_id"], {"target": "127.0.0.1", "port": "80"})

        assert result["status"] == "pending_approval"
        assert len(result["pending_or_denied"]) > 0
        assert result["pending_or_denied"][0]["outcome"] == "pending_approval"

    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_out_of_scope_target_denied(self, mock_exec, mock_llm):
        mock_llm.return_value = _fake_llm_response("nmap", {"target": "10.0.0.99", "ports": "80"})
        mock_exec.return_value = {"error": "Target '10.0.0.99' is not in the engagement scope"}

        session = create_session("eng-test-3", "scan target")
        orchestrator_step(session["session_id"])
        result = confirm_params(session["session_id"], {"target": "10.0.0.99", "ports": "80"})

        assert result["status"] == "active"
        denied = [a for a in result["action_history"] if a.get("outcome") == "denied"]
        assert len(denied) > 0
        assert "not in the engagement scope" in denied[0].get("reason", "")

    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_finish_engagement_signal(self, mock_exec, mock_llm):
        mock_llm.return_value = _fake_llm_response(
            "finish_engagement",
            {"summary": "Completed scan. Found 3 open ports."},
        )

        session = create_session("eng-test-4", "scan and summarize")
        result = orchestrator_step(session["session_id"])

        assert result["status"] == "completed"
        assert result["summary"] == "Completed scan. Found 3 open ports."
        assert len(result["action_history"]) > 0
        assert result["action_history"][-1]["type"] == "summary"

    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_pending_approval_resolved_on_next_step(self, mock_exec, mock_llm):
        mock_llm.return_value = _fake_llm_response("nuclei", {"target": "127.0.0.1"})
        mock_exec.return_value = {
            "status": "pending_approval",
            "approval_id": "apr-resolve-001",
        }

        session = create_session("eng-test-5", "check vulns")
        orchestrator_step(session["session_id"])
        result = confirm_params(session["session_id"], {"target": "127.0.0.1"})
        assert result["status"] == "pending_approval"

        session_data = load_session(session["session_id"])
        assert session_data is not None
        session_data["_pending_approval_id"] = "apr-resolve-001"
        from orchestrator.state import save_session
        save_session(session_data)

        mock_llm.return_value = _fake_llm_response("finish_engagement", {"summary": "Complete."})
        mock_exec.return_value = {"job_id": "sbox-vuln-001"}

        with patch("orchestrator.engine.get_approval") as mock_get_approval:
            mock_get_approval.return_value = {
                "status": "approved",
                "result_job_id": "sbox-resolved-001",
                "deny_reason": None,
            }
            with patch("orchestrator.engine.SandboxExecutor.get_result") as mock_get:
                mock_get.return_value = {
                    "status": "completed",
                    "exit_code": 0,
                    "findings": {
                        "tool": "nuclei",
                        "findings": [{"type": "vulnerability", "detail": {"name": "Test Vuln", "severity": "medium"}}],
                    },
                }
                result2 = orchestrator_step(session["session_id"], user_message="continue")

        assert result2["status"] == "completed"
        assert len(result2["findings_so_far"]) >= 1

    @patch("orchestrator.engine.llm_decide")
    def test_unknown_tool_handled_gracefully(self, mock_llm):
        mock_llm.return_value = _fake_llm_response("nonexistent_tool", {"target": "test"})
        session = create_session("eng-test-6", "test unknown tool")
        result = orchestrator_step(session["session_id"])
        assert result["status"] == "active"
        assert len(result["action_history"]) > 0

    @patch("orchestrator.engine.llm_decide")
    def test_conversational_reply_keeps_session_active(self, mock_llm):
        mock_llm.return_value = _fake_llm_response(content="Hello! I can help scan your targets.")
        session = create_session("eng-test-7", "scan example.com")
        result = orchestrator_step(session["session_id"], user_message="hello")
        assert result["status"] == "active"
        assert result["action_history"][-1]["type"] == "chat"
        assert result["action_history"][-1]["content"] == "Hello! I can help scan your targets."

    @patch("orchestrator.engine.llm_decide")
    def test_finish_flag_ends_session(self, mock_llm):
        mock_llm.return_value = _fake_llm_response(
            content="Done. Found 2 ports open.",
            finish=True,
        )

        session = create_session("eng-test-8", "scan and wrap up")
        result = orchestrator_step(session["session_id"])
        assert result["status"] == "completed"
        assert result["summary"] == "Done. Found 2 ports open."

    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_goal_not_overwritten_by_chat_message(self, mock_exec, mock_llm):
        mock_llm.return_value = _fake_llm_response(content="Sure, tell me more.")
        session = create_session("eng-test-9", "scan example.com")
        orchestrator_step(session["session_id"], user_message="what tools do you have?")
        loaded = load_session(session["session_id"])
        assert loaded["goal"] == "scan example.com"

    @patch("orchestrator.engine.llm_decide")
    def test_user_message_passed_to_llm(self, mock_llm):
        mock_llm.return_value = _fake_llm_response(content="ok")
        session = create_session("eng-test-10", "scan example.com")
        orchestrator_step(session["session_id"], user_message="continue please")
        args, kwargs = mock_llm.call_args
        assert kwargs.get("user_message") == "continue please"

    @patch("orchestrator.engine.llm_decide")
    def test_followup_user_message_persisted_for_context(self, mock_llm):
        mock_llm.side_effect = [
            _fake_llm_response(content="I'm sorry, I can't assist with that."),
            _fake_llm_response(content="Because it is outside the authorized engagement scope."),
        ]
        session = create_session("eng-test-13", "hi")
        orchestrator_step(session["session_id"], user_message="can u hack a device")
        loaded = load_session(session["session_id"])
        assert not any(a.get("type") == "user" for a in loaded["action_history"]), (
            "Initial creation message should not be stored (goal covers it)"
        )
        orchestrator_step(session["session_id"], user_message="why is that")
        loaded = load_session(session["session_id"])
        user_entries = [a for a in loaded["action_history"] if a.get("type") == "user"]
        assert len(user_entries) == 1
        assert user_entries[0]["content"] == "why is that"

    def test_compact_state_includes_conversation(self):
        state = {
            "engagement_id": "eng-x",
            "goal": "scan example.com",
            "tools_already_run": [],
            "pending_or_denied": [],
            "findings_so_far": [],
            "action_history": [
                {"type": "user", "content": "can u hack a device", "timestamp": "2026-01-01T00:00:01"},
                {"type": "chat", "content": "I'm sorry, I can't assist.", "timestamp": "2026-01-01T00:00:02"},
                {"type": "action", "tool_name": "nmap", "target": "example.com",
                 "outcome": "completed", "timestamp": "2026-01-01T00:00:03"},
            ],
        }
        compact = _build_compact_state(state)
        assert "conversation" in compact
        assert compact["conversation"][0] == {"role": "user", "text": "can u hack a device"}
        assert compact["conversation"][1] == {"role": "assistant", "text": "I'm sorry, I can't assist."}
        assert "ran nmap on example.com: completed" in compact["conversation"][2]["text"]

    def test_compact_state_includes_tool_history_and_candidates(self):
        from orchestrator.investigate import blackboard
        board = blackboard.empty_blackboard()
        board["_initialized"] = True
        board["action_scores"] = [{"capability": "network_discovery", "target": "example.com"}]
        state = {
            "findings_so_far": [], "tools_already_run": ["nmap"], "pending_or_denied": [],
            "investigation": board,
        }
        compact = _build_compact_state(state)
        assert compact["tools_already_run"] == ["nmap"]
        assert compact["investigation"]["phase"] == blackboard.PHASE_RECON
        assert compact["candidate_actions"][0]["capability"] == "network_discovery"

    @patch("orchestrator.engine.llm_decide")
    def test_plan_request_gets_chat_reply_not_execution(self, mock_llm):
        mock_llm.return_value = _fake_llm_response(
            content="I would start with a port scan, then a web scan...",
            finish=False,
        )
        session = create_session("eng-test-11", "scan example.com")
        result = orchestrator_step(
            session["session_id"],
            user_message="first let me know how you would go on to check vulnerabilities, later i will tell you to execute",
        )
        assert result["status"] == "active"
        assert result["action_history"][-1]["type"] == "chat"
        assert not any(
            a.get("type") == "action" for a in result["action_history"]
        ), "No tool should have run for a plan request"


class TestIntentEnvelope:
    def test_parse_execute_envelope_with_action(self):
        env = _parse_envelope(
            '{"intent": "execute", "reply": "Scanning now.", '
            '"action": {"name": "nmap", "arguments": {"target": "example.com", "ports": "80"}}}'
        )
        assert env is not None
        resp = _envelope_to_response(env)
        assert resp.is_tool_call is True
        assert resp.tool_name == "nmap"
        assert resp.arguments["target"] == "example.com"
        assert resp.intent == "execute"

    def test_parse_plan_envelope_never_runs_action(self):
        env = _parse_envelope(
            '{"intent": "plan", "reply": "I would scan ports first, then check the web server.", '
            '"action": {"name": "nmap", "arguments": {"target": "example.com"}}}'
        )
        resp = _envelope_to_response(env)
        assert resp.is_tool_call is False
        assert "ports first" in resp.content
        assert resp.intent == "plan"

    def test_parse_conversation_envelope(self):
        env = _parse_envelope('{"intent": "conversation", "reply": "Sure, I can help!", "action": null}')
        resp = _envelope_to_response(env)
        assert resp.is_tool_call is False
        assert resp.content == "Sure, I can help!"
        assert resp.intent == "conversation"

    def test_parse_finish_envelope(self):
        env = _parse_envelope(
            '{"intent": "execute", "reply": "Done.", '
            '"action": {"name": "finish_engagement", "arguments": {"summary": "All scans complete."}}}'
        )
        resp = _envelope_to_response(env)
        assert resp.is_tool_call is False
        assert resp.finish is True
        assert resp.content == "All scans complete."

    def test_parse_envelope_ignores_plain_text(self):
        assert _parse_envelope("I would start with a port scan, then run a web scan.") is None

    def test_execute_envelope_with_description_as_name(self):
        env = _parse_envelope(
            '{"intent": "execute", "reply": "Scanning.", '
            '"action": {"name": "nmap Port and service scanner (passive - auto-executes immediately, no approval needed) [attack_class: recon]", '
            '"arguments": {"target": "test-target.local", "ports": "80"}}}'
        )
        resp = _envelope_to_response(env)
        assert resp.is_tool_call is True
        assert resp.tool_name == "nmap"
        assert resp.arguments["target"] == "test-target.local"

    def test_execute_envelope_with_unresolvable_name_does_not_run(self):
        env = _parse_envelope(
            '{"intent": "execute", "reply": "Running something.", '
            '"action": {"name": "totally-made-up-tool", "arguments": {"target": "example.com"}}}'
        )
        resp = _envelope_to_response(env)
        assert resp.is_tool_call is False

    def test_parse_envelope_handles_fences(self):
        env = _parse_envelope(
            '```json\n{"intent": "execute", "reply": "ok", '
            '"action": {"name": "subfinder", "arguments": {"target": "example.com"}}}\n```'
        )
        assert env is not None
        assert _envelope_to_response(env).tool_name == "subfinder"

    def test_unknown_intent_falls_back(self):
        env = _parse_envelope('{"intent": "maybe", "reply": "hi", "action": null}')
        assert _envelope_to_response(env) is None


class TestIntentClassifier:
    @pytest.mark.parametrize("message", [
        "What can you do?",
        "What tools do you have?",
        "What is Nmap?",
        "Explain Gobuster",
        "What happened?",
    ])
    def test_conversation_messages_never_select_execution(self, message):
        assert classify_intent(message) == CONVERSATION

    @pytest.mark.parametrize("message", [
        "How would you assess an ecommerce website?",
        "How would you approach testphp.vulnweb.com?",
        "I want to assess https://testphp.vulnweb.com. How would you approach it?",
        "What steps would you take before testing?",
    ])
    def test_planning_questions_take_precedence_over_execution_words(self, message):
        assert classify_intent(message) == PLAN

    @pytest.mark.parametrize("message", [
        "Scan testphp.vulnweb.com",
        "Run Nmap against scanme.nmap.org",
        "Begin assessment now",
    ])
    def test_explicit_commands_select_execution(self, message):
        assert classify_intent(message) == EXECUTION

    def test_ambiguous_request_defaults_to_conversation(self):
        assert classify_intent("testphp.vulnweb.com") == CONVERSATION

    def test_continue_is_execution_only_after_a_started_investigation(self):
        assert classify_intent("continue") == CONVERSATION
        assert classify_intent("continue", {"action_history": [{"type": "action"}]}) == EXECUTION

    @patch("orchestrator.engine.llm_decide")
    def test_non_execution_turn_discards_unexpected_tool_call(self, mock_llm):
        mock_llm.return_value = _fake_llm_response(
            "nmap", {"target": "example.com", "ports": "1-1000"}, "Here is an explanation."
        )
        session = create_session("eng-intent-gate", "security testing")
        result = orchestrator_step(session["session_id"], user_message="What is Nmap?")
        assert result["pending_param_confirm"] is None
        assert not any(a.get("type") == "action" for a in result["action_history"])
        assert result["action_history"][-1]["type"] == "chat"

    @patch("orchestrator.engine.llm_decide")
    def test_execution_turn_still_creates_parameter_confirmation(self, mock_llm):
        mock_llm.return_value = _fake_llm_response(
            "nmap", {"target": "example.com", "ports": "1-1000"}, "Scanning."
        )
        session = create_session("eng-intent-exec", "security testing")
        result = orchestrator_step(session["session_id"], user_message="Scan example.com")
        assert result["status"] == "awaiting_params"
        assert result["pending_param_confirm"]["tool_name"] == "nmap"


class TestIntegration:
    def test_generated_schemas_match_registry(self):
        from tool_registry.registry import get_all_tools
        schemas = generate_tool_schemas()
        schema_names = [s["function"]["name"] for s in schemas if s["function"]["name"] != "finish_engagement"]

        registry_tools = get_all_tools()
        registry_names = [t["name"] for t in registry_tools]

        assert set(schema_names) == set(registry_names)

    def test_compact_state_no_balloon(self):
        state = {
            "goal": "scan target for vulnerabilities",
            "tools_already_run": ["nmap", "nikto", "gobuster"],
            "pending_or_denied": [
                {"tool_name": "sqlmap", "target": "test.local", "outcome": "denied", "reason": "not needed"},
            ],
            "findings_so_far": [
                {
                    "type": "port_open",
                    "detail": {"port": p, "service": "http", "version": "nginx 1.24"},
                    "_tool": "nmap",
                    "_job_id": f"sbox-{p:04d}",
                }
                for p in range(100)
            ],
        }
        compact = _build_compact_state(state)

        assert "findings_truncated" in compact
        assert compact["findings_truncated"] == 100
        assert len(compact["findings_so_far"]) == 50
        assert compact["findings_so_far"][0]["type"] == "port_open"
        assert compact["findings_so_far"][0]["port"] is not None

        raw_keys = {"stdout", "stderr", "command", "exit_code"}
        for f in compact["findings_so_far"]:
            for key in raw_keys:
                assert key not in f, f"Compact state should not contain raw '{key}'"


class TestFollowUpDegeneration:
    """The model sometimes repeats its previous reply verbatim on a follow-up
    question. decide() must retry once with a corrective note."""

    def _state(self):
        return {
            "engagement_id": "eng-fu",
            "goal": "hi",
            "action_history": [
                {"type": "user", "content": "can u hack a device", "timestamp": "t1"},
                {"type": "chat", "content": "I'm sorry, but I can't assist with that request.", "timestamp": "t2"},
            ],
            "findings_so_far": [],
            "tools_already_run": [],
            "pending_or_denied": [],
        }

    def test_verbatim_repeat_retries_with_note(self):
        repeat = LLMResponse(is_tool_call=False, content="I'm sorry, but I can't assist with that request.")
        good = LLMResponse(is_tool_call=False, content="Because the target is not in your authorized engagement scope.")
        with patch("orchestrator.llm_client._complete", side_effect=[repeat, good]) as mock:
            result = decide(self._state(), user_message="why is that")
        assert result.content == "Because the target is not in your authorized engagement scope."
        assert mock.call_count == 2
        second_user_text = mock.call_args_list[1][0][2]
        assert "follow-up question" in second_user_text
        assert "do NOT repeat" in second_user_text

    def test_no_retry_when_reply_is_new(self):
        good = LLMResponse(is_tool_call=False, content="Totally different answer.")
        with patch("orchestrator.llm_client._complete", side_effect=[good]) as mock:
            result = decide(self._state(), user_message="why is that")
        assert result.content == "Totally different answer."
        assert mock.call_count == 1

    def test_no_retry_on_tool_call(self):
        tool = LLMResponse(is_tool_call=True, tool_name="nmap", arguments={"target": "example.com"})
        with patch("orchestrator.llm_client._complete", side_effect=[tool]) as mock:
            result = decide(self._state(), user_message="scan example.com")
        assert result.is_tool_call
        assert mock.call_count == 1


class TestConcurrentJobGuard:
    @patch("orchestrator.engine.llm_decide")
    @patch("orchestrator.engine.execute_action")
    def test_no_second_job_kicked_while_one_executes(self, mock_exec, mock_llm):
        mock_llm.return_value = _fake_llm_response("nmap", {"target": "127.0.0.1", "ports": "80"})
        mock_exec.return_value = {"job_id": "sbox-first-001"}

        session = create_session("eng-test-15", "scan")
        orchestrator_step(session["session_id"])
        result = confirm_params(session["session_id"], {"target": "127.0.0.1", "ports": "80"})
        assert result["action_history"][-1]["outcome"] == "executing"

        # User sends another message while the first scan is still running.
        mock_llm.return_value = _fake_llm_response("nikto", {"target": "127.0.0.1", "port": "80"})
        result2 = orchestrator_step(session["session_id"], user_message="also run nikto")
        actions = [a for a in result2["action_history"] if a.get("type") == "action"]
        assert len(actions) == 1, "should not kick a second job while one is executing"
        assert actions[-1]["outcome"] == "executing"
        # The message is still stored so it is not lost.
        assert any(a.get("type") == "user" for a in result2["action_history"])
