"""Tests for the investigation-loop reasoning components.

Covers the blackboard, the Mission/Investigation planner, the Evidence
Analyzer, the Knowledge Manager, the Action Selector and the parser
enrichment layer that feeds them. These components are the "think like an
operator" half of the orchestrator; the LLM remains the final decision-maker,
so the tests assert the deterministic heuristics, not LLM behaviour.
"""

from orchestrator.investigate import blackboard
from orchestrator.investigate import planner
from orchestrator.investigate import analyst
from orchestrator.investigate import knowledge
from orchestrator.investigate import selector
from tool_registry import capabilities as capability_resolver
from tool_registry.parsers import enrich


def _tools_for(capability_id: str) -> set:
    """Concrete tools registered to implement a capability (regardless of install state)."""
    return {tc.tool_name for tc in capability_resolver.resolve(capability_id).candidates}


def _session(goal: str = "assess the security of the engagement target") -> dict:
    return {
        "session_id": "orch-test",
        "engagement_id": "eng-test",
        "goal": goal,
        "findings_so_far": [],
        "tools_already_run": [],
        "action_history": [],
        "investigation": None,
    }


class TestBlackboard:
    def test_ensure_creates_fresh_board(self):
        s = _session()
        board = blackboard.ensure_blackboard(s)
        assert board is s["investigation"]
        assert board["phase"] == blackboard.PHASE_RECON
        assert board["confidence"] == 0.0
        assert board["known_facts"] == []
        assert board["hypotheses"] == []

    def test_ensure_reuses_existing_board(self):
        s = _session()
        b1 = blackboard.ensure_blackboard(s)
        b1["known_facts"].append({"x": 1})
        b2 = blackboard.ensure_blackboard(s)
        assert b2 is b1

    def test_add_fact_is_deduplicated_by_signature(self):
        board = blackboard.empty_blackboard()
        blackboard.add_fact(board, "port 80 is open", source="nmap", target="a.com",
                            confidence=0.8, evidence="e", signature="s1")
        blackboard.add_fact(board, "port 80 is open", source="nmap", target="a.com",
                            confidence=0.8, evidence="e", signature="s1")
        assert len(board["known_facts"]) == 1

    def test_add_hypothesis_raises_confidence_not_duplicates(self):
        board = blackboard.empty_blackboard()
        blackboard.add_hypothesis(board, "a.com runs a web app", confidence=0.4,
                                  support="port 80")
        blackboard.add_hypothesis(board, "a.com runs a web app", confidence=0.8,
                                  support="header hints")
        assert len(board["hypotheses"]) == 1
        h = board["hypotheses"][0]
        assert h["confidence"] == 0.8
        assert h["status"] == "supported"
        assert len(h["evidence_for"]) == 2

    def test_refute_hypothesis(self):
        board = blackboard.empty_blackboard()
        blackboard.add_hypothesis(board, "sql injection", confidence=0.7, support="x")
        blackboard.refute_hypothesis(board, "sql injection", reason="payload did not trigger")
        h = board["hypotheses"][0]
        assert h["status"] == "refuted"
        assert h["confidence"] == 0.0
        assert "payload did not trigger" in h["evidence_against"]

    def test_unknown_lifecycle(self):
        board = blackboard.empty_blackboard()
        assert blackboard.add_unknown(board, "what is exposed?")
        assert not blackboard.add_unknown(board, "what is exposed?")
        assert len(blackboard.open_unknowns(board)) == 1
        blackboard.answer_unknown(board, "what is exposed?", source="nmap")
        assert blackboard.open_unknowns(board) == []

    def test_service_asset_marks_interesting(self):
        board = blackboard.empty_blackboard()
        blackboard.note_service_asset(board, "a.com", 443, "https", is_interesting=True)
        blackboard.note_service_asset(board, "a.com", 22, "ssh", is_interesting=True)
        asset = board["assets"][0]
        assert asset["ports"] == [443, 22]
        assert asset["interesting"] is True
        assert 443 in board["interesting_ports"]
        assert "https" in board["interesting_services"]

    def test_path_and_vuln_tracking(self):
        board = blackboard.empty_blackboard()
        blackboard.note_path_asset(board, "a.com", "/admin", interesting=True)
        blackboard.add_potential_vulnerability(
            board, name="XSS", severity="high", target="a.com", path="/admin",
            source="nuclei")
        assert "/admin" in board["interesting_paths"]
        assert len(board["potential_vulnerabilities"]) == 1
        assert board["potential_vulnerabilities"][0]["status"] == "suspected"


class TestPlanner:
    def test_initialize_derives_objective_and_unknowns_from_goal(self):
        s = _session("find web vulnerabilities on the site")
        board = planner.initialize(s, scope={"targets": ["example.com"]})
        assert board["_initialized"] is True
        assert any("web" in u["question"].lower() for u in board["unknowns"])
        assert any("example.com" in u["question"] for u in board["unknowns"])

    def test_initialize_seeds_hypothesis_for_web_goal(self):
        s = _session("check the web application for SQL injection")
        board = planner.initialize(s, scope={"targets": ["shop.example.com"]})
        assert any("web application" in h["hypothesis"] for h in board["hypotheses"])

    def test_initialize_is_idempotent(self):
        s = _session("web goal")
        scope = {"targets": ["example.com"]}
        b1 = planner.initialize(s, scope=scope)
        n1 = len(b1["unknowns"])
        b2 = planner.initialize(s, scope=scope)
        assert len(b2["unknowns"]) == n1

    def test_advance_progresses_phase_and_confidence(self):
        s = _session()
        board = planner.initialize(s, scope={"targets": ["example.com"]})
        board["assets"] = [{"target": "example.com", "ports": [80], "services": ["http"],
                            "paths": [], "type": "host"}]
        board["known_facts"] = []
        board["hypotheses"] = []
        board["potential_vulnerabilities"] = []
        board["completed_actions"] = ["nmap@example.com"]
        planner.advance(board, candidates=[{"tool_name": "nuclei", "target": "example.com"}])
        assert board["phase"] == blackboard.PHASE_WEB_RECON
        assert board["confidence"] > 0.0
        assert board["next_objective"]

    def test_advance_does_not_enter_report_while_candidates_exist(self):
        s = _session()
        board = planner.initialize(s, scope={"targets": ["example.com"]})
        planner.advance(board, candidates=[{"tool_name": "nmap", "target": "example.com"}])
        assert board["phase"] != blackboard.PHASE_REPORT

    def test_advance_enters_report_only_when_no_candidates_left(self):
        board = blackboard.empty_blackboard()
        board["assets"] = [{"target": "a.com", "ports": [80], "services": ["http"],
                            "paths": [], "type": "host"}]
        board["hypotheses"] = [{"hypothesis": "web", "status": "supported",
                                "confidence": 0.9, "evidence_for": [], "evidence_against": []}]
        planner.advance(board, candidates=[])
        assert board["phase"] == blackboard.PHASE_REPORT


class TestAnalyst:
    def test_absorb_port_findings_into_board(self):
        s = _session()
        board = blackboard.ensure_blackboard(s)
        s["findings_so_far"] = [
            {"type": "port_open", "_tool": "nmap", "_job_id": "j1",
             "detail": {"host": "example.com", "port": 80, "protocol": "tcp",
                        "service": "http", "interestingness": 1.0, "confidence": 0.7}},
        ]
        s["action_history"] = [
            {"type": "action", "tool_name": "nmap", "target": "example.com",
             "outcome": "completed", "job_id": "j1"},
        ]
        analyst.absorb(s)
        assert board["assets"]
        assert board["assets"][0]["ports"] == [80]
        assert 80 in board["interesting_ports"]
        assert board["confidence"] >= 0.0

    def test_absorb_is_idempotent(self):
        s = _session()
        board = blackboard.ensure_blackboard(s)
        s["findings_so_far"] = [
            {"type": "port_open", "_tool": "nmap", "_job_id": "j1",
             "detail": {"host": "example.com", "port": 80, "service": "http",
                        "interestingness": 1.0, "confidence": 0.7}},
        ]
        s["action_history"] = [
            {"type": "action", "tool_name": "nmap", "target": "example.com",
             "outcome": "completed", "job_id": "j1"},
        ]
        analyst.absorb(s)
        analyst.absorb(s)
        assert len(board["known_facts"]) == 1
        assert len(board["assets"]) == 1

    def test_absorb_sql_injection_creates_vulnerability(self):
        s = _session()
        board = blackboard.ensure_blackboard(s)
        s["findings_so_far"] = [
            {"type": "sql_injection", "_tool": "sqlmap", "_job_id": "j2",
             "detail": {"host": "example.com", "parameter": "id", "method": "GET"}},
        ]
        s["action_history"] = [
            {"type": "action", "tool_name": "sqlmap", "target": "http://example.com",
             "outcome": "completed", "job_id": "j2"},
        ]
        analyst.absorb(s)
        assert board["potential_vulnerabilities"]
        assert board["potential_vulnerabilities"][0]["severity"] == "high"


class TestKnowledge:
    def _board_with_web_asset(self):
        board = blackboard.empty_blackboard()
        board["assets"] = [{"target": "example.com", "type": "host",
                            "ports": [80], "services": ["http"], "paths": [],
                            "parent": None, "interesting": True, "confidence": 0.7}]
        board["_initialized"] = True
        return board

    def test_recon_candidates_for_unprobed_scope(self):
        board = blackboard.empty_blackboard()
        board["_initialized"] = True
        cands = knowledge.generate_candidates(board, ["example.com"], goal="assess")
        caps = {c["capability"] for c in cands}
        assert "network_discovery" in caps
        assert "subdomain_enumeration" in caps
        assert "nmap" in _tools_for("network_discovery")
        assert "subfinder" in _tools_for("subdomain_enumeration")
        nmap_c = next(c for c in cands if c["capability"] == "network_discovery")
        assert nmap_c["info_gain"] > 0
        assert nmap_c["risk"] < 0.5

    def test_web_candidates_appear_for_web_asset(self):
        board = self._board_with_web_asset()
        board["completed_actions"] = ["network_discovery@example.com", "subdomain_enumeration@example.com"]
        cands = knowledge.generate_candidates(board, ["example.com"], goal="assess")
        caps = {c["capability"] for c in cands}
        assert "technology_detection" in caps
        assert "directory_discovery" in caps
        assert "web_server_audit" in caps
        assert "nuclei" in _tools_for("technology_detection")
        assert "gobuster" in _tools_for("directory_discovery")
        assert "nikto" in _tools_for("web_server_audit")

    def test_no_duplicate_candidates_for_done_actions(self):
        board = self._board_with_web_asset()
        board["completed_actions"] = ["network_discovery@example.com", "technology_detection@example.com",
                                      "subdomain_enumeration@example.com"]
        cands = knowledge.generate_candidates(board, ["example.com"], goal="assess")
        done = [c for c in cands if c["capability"] == "technology_detection"]
        assert done == []

    def test_hydra_candidate_only_for_brute_goal(self):
        board = self._board_with_web_asset()
        board["assets"][0]["ports"] = [22]
        board["assets"][0]["services"] = ["ssh"]
        board["completed_actions"] = ["network_discovery@example.com", "subdomain_enumeration@example.com"]
        cands = knowledge.generate_candidates(board, ["example.com"], goal="test weak passwords")
        assert any(c["capability"] == "credential_attack" for c in cands)
        assert "hydra" in _tools_for("credential_attack")
        cands2 = knowledge.generate_candidates(board, ["example.com"], goal="web recon")
        assert not any(c["capability"] == "credential_attack" for c in cands2)

    def test_host_out_of_scope_never_suggested(self):
        board = self._board_with_web_asset()
        cands = knowledge.generate_candidates(board, ["example.com"], goal="assess")
        for c in cands:
            assert "example.com" in c["target"]

    def test_summarize_gaps_reports_open_questions(self):
        board = blackboard.empty_blackboard()
        blackboard.add_unknown(board, "what ports are open?", importance=0.9)
        gap = knowledge.summarize_gaps(board)
        assert "ports" in gap


class TestSelector:
    def _candidates(self):
        return [
            {"capability": "network_discovery", "target": "a.com", "params": {}, "objective": "x",
             "info_gain": 0.9, "cost": 0.2, "risk": 0.05, "likelihood": 0.95,
             "phase": blackboard.PHASE_RECON, "note": ""},
            {"capability": "sql_injection_validation", "target": "a.com", "params": {}, "objective": "y",
             "info_gain": 0.8, "cost": 0.8, "risk": 0.5, "likelihood": 0.3,
             "phase": blackboard.PHASE_EXPLOITATION, "note": ""},
        ]

    def test_rank_orders_by_value_heuristics(self):
        board = blackboard.empty_blackboard()
        ranked = selector.rank(self._candidates(), board)
        assert ranked[0]["capability"] == "network_discovery"
        assert ranked[0]["score"] > ranked[1]["score"]
        assert "rationale" in ranked[0]

    def test_rank_persists_shortlist_to_board(self):
        board = blackboard.empty_blackboard()
        selector.rank(self._candidates(), board)
        assert board["action_scores"]
        assert len(board["action_scores"]) == 2

    def test_rank_phase_fit_penalizes_early_exploitation(self):
        c1 = {"capability": "sql_injection_validation", "target": "a.com", "params": {}, "objective": "y",
              "info_gain": 0.9, "cost": 0.8, "risk": 0.5, "likelihood": 0.9,
              "phase": blackboard.PHASE_EXPLOITATION, "note": ""}
        board = blackboard.empty_blackboard()  # phase == recon
        ranked = selector.rank([c1], board)
        # The exploitation candidate should be phase-penalized (score < pure sum).
        assert ranked[0]["score"] < (0.4 * 0.9 + 0.25 * 0.9 + 0.15 - 0.1 * 0.8 - 0.1 * 0.5)


class TestEnrich:
    def test_port_open_enrichment(self):
        f = enrich.enrich("nmap", {
            "type": "port_open",
            "detail": {"host": "a.com", "port": 80, "service": "http", "version": "nginx 1.24"},
        })
        assert f["detail"]["confidence"] == 0.7
        assert f["detail"]["interestingness"] == 1.0
        assert f["detail"]["technology"] == "nginx"
        assert any(fu["tool"] == "nuclei" for fu in f["detail"]["follow_ups"])
        assert f["detail"]["relationships"] == [{"type": "exposes_service", "value": "http"}]

    def test_web_follow_ups_guide_next_steps(self):
        f = enrich.enrich("nmap", {
            "type": "port_open",
            "detail": {"host": "a.com", "port": 443, "service": "https"},
        })
        tools = {fu["tool"] for fu in f["detail"]["follow_ups"]}
        assert {"nuclei", "gobuster", "nikto"} <= tools

    def test_vulnerability_severity_maps_to_confidence(self):
        f = enrich.enrich("nuclei", {
            "type": "vulnerability",
            "detail": {"name": "XSS", "severity": "high", "url": "http://a.com"},
        })
        assert f["detail"]["confidence"] == 0.8
        assert f["detail"]["interestingness"] == 0.85

    def test_subdomain_relationship_parent(self):
        f = enrich.enrich("subfinder", {
            "type": "subdomain",
            "detail": {"subdomain": "api.example.com"},
        })
        assert f["detail"]["parent"] == "example.com"
        assert f["detail"]["relationships"] == [{"type": "child_of", "value": "example.com"}]

    def test_credential_found_interesting(self):
        f = enrich.enrich("hydra", {
            "type": "credential_found",
            "detail": {"host": "a.com", "port": 22, "service": "ssh",
                       "login": "root", "password": "root"},
        })
        assert f["detail"]["interestingness"] == 1.0
        assert f["detail"]["confidence"] == 0.9

    def test_ssh_service_is_interesting(self):
        f = enrich.enrich("nmap", {
            "type": "port_open",
            "detail": {"host": "a.com", "port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
        })
        assert f["detail"]["interestingness"] == 1.0
        assert f["detail"]["technology"] == "OpenSSH"
        assert f["detail"]["follow_ups"] == []
