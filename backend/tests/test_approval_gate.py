import os
import json
import time
import threading
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from approval_gate.gate import (
    create_approval,
    get_approval,
    list_approvals,
    approve_approval,
    deny_approval,
    set_approval_job_id,
    APPROVALS_PATH,
    APPROVAL_EXPIRY_MINUTES,
    _load_approvals,
    _is_expired,
)
from sandbox_executor.executor import execute_action, SandboxExecutor
from scope_engine import storage

TEST_APPROVALS_PATH = Path(__file__).parent.parent / "data" / "test_approvals.json"


def _cleanup_approvals():
    if TEST_APPROVALS_PATH.exists():
        TEST_APPROVALS_PATH.unlink()


def _use_test_path():
    import approval_gate.gate as gate_mod
    gate_mod.APPROVALS_PATH = TEST_APPROVALS_PATH
    gate_mod._approvals.clear()
    _cleanup_approvals()


def _reset_path():
    import approval_gate.gate as gate_mod
    gate_mod.APPROVALS_PATH = APPROVALS_PATH


class TestApprovalGate:
    def setup_method(self):
        _use_test_path()
        self.eng_id = "test-approval-eng"
        scope = storage.load_scope(self.eng_id)
        if scope is None:
            storage.save_scope({
                "engagement_id": self.eng_id,
                "engagement_name": "Approval Test",
                "targets": ["127.0.0.1", "test-target.local"],
                "excluded_targets": [],
                "start_time": "2026-01-01T00:00:00+00:00",
                "end_time": "2030-01-01T00:00:00+00:00",
                "allowed_attack_classes": ["recon", "web", "network"],
                "authorization_contact": {"name": "T", "email": "t@t.com", "role": "t"},
                "emergency_contact": "t",
            })

    def teardown_method(self):
        _cleanup_approvals()

    def test_1_create_approval(self):
        record = create_approval(
            engagement_id="eng-1",
            tool_name="nikto",
            params={"target": "127.0.0.1", "port": "80"},
            risk_tier="active_scan",
            attack_class="web",
            target="127.0.0.1",
        )
        assert record["status"] == "pending"
        assert record["approval_id"].startswith("apr-")
        assert record["tool_name"] == "nikto"
        assert record["risk_tier"] == "active_scan"
        assert record["params"]["target"] == "127.0.0.1"

    def test_2_get_approval(self):
        created = create_approval("eng-1", "gobuster", {"target": "http://example.com"}, "active_scan", "web", "http://example.com")
        fetched = get_approval(created["approval_id"])
        assert fetched is not None
        assert fetched["approval_id"] == created["approval_id"]
        assert fetched["status"] == "pending"

    def test_3_get_nonexistent(self):
        assert get_approval("apr-9999") is None

    def test_4_list_approvals(self):
        create_approval("eng-1", "nikto", {"target": "10.0.0.1"}, "active_scan", "web", "10.0.0.1")
        create_approval("eng-2", "nuclei", {"target": "10.0.0.2"}, "active_scan", "web", "10.0.0.2")
        all_reqs = list_approvals()
        assert len(all_reqs) == 2
        eng1_reqs = list_approvals(engagement_id="eng-1")
        assert len(eng1_reqs) == 1
        assert eng1_reqs[0]["engagement_id"] == "eng-1"

    def test_5_approve_approval(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        updated = approve_approval(created["approval_id"], decided_by="tester")
        assert updated is not None
        assert updated["status"] == "approved"
        assert updated["decided_by"] == "tester"
        assert updated["decided_at"] is not None

        fetched = get_approval(created["approval_id"])
        assert fetched is not None
        assert fetched["status"] == "approved"

    def test_6_cannot_approve_twice(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        approve_approval(created["approval_id"])
        second = approve_approval(created["approval_id"])
        assert second is None

    def test_7_deny_approval(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        updated = deny_approval(created["approval_id"], decided_by="tester", reason="Not needed")
        assert updated is not None
        assert updated["status"] == "denied"
        assert updated["deny_reason"] == "Not needed"

        fetched = get_approval(created["approval_id"])
        assert fetched is not None
        assert fetched["status"] == "denied"

    def test_8_cannot_deny_twice(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        deny_approval(created["approval_id"])
        second = deny_approval(created["approval_id"])
        assert second is None

    def test_9_cannot_approve_after_deny(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        deny_approval(created["approval_id"])
        result = approve_approval(created["approval_id"])
        assert result is None

    def test_10_cannot_deny_after_approve(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        approve_approval(created["approval_id"])
        result = deny_approval(created["approval_id"])
        assert result is None

    def test_11_expiry_auto_transitions(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        from approval_gate.gate import _is_expired
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=APPROVAL_EXPIRY_MINUTES + 1)).isoformat()
        import approval_gate.gate as gate_mod
        stored = gate_mod._load_approvals()
        stored[created["approval_id"]]["requested_at"] = old_time
        gate_mod._save_approvals(stored)

        fetched = get_approval(created["approval_id"])
        assert fetched is not None
        assert fetched["status"] == "expired"

    def test_12_cannot_approve_expired(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        import approval_gate.gate as gate_mod
        stored = gate_mod._load_approvals()
        stored[created["approval_id"]]["requested_at"] = (
            datetime.now(timezone.utc) - timedelta(minutes=APPROVAL_EXPIRY_MINUTES + 1)
        ).isoformat()
        gate_mod._save_approvals(stored)

        result = approve_approval(created["approval_id"])
        assert result is None

        fetched = get_approval(created["approval_id"])
        assert fetched["status"] == "expired"

    def test_13_set_job_id(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        approve_approval(created["approval_id"])
        set_approval_job_id(created["approval_id"], "sbox-9999")
        fetched = get_approval(created["approval_id"])
        assert fetched["result_job_id"] == "sbox-9999"

    def test_14_durable_storage_survives_reload(self):
        created = create_approval("eng-1", "nikto", {"target": "127.0.0.1"}, "active_scan", "web", "127.0.0.1")
        assert TEST_APPROVALS_PATH.exists()
        raw = json.loads(TEST_APPROVALS_PATH.read_text())
        assert created["approval_id"] in raw
        assert raw[created["approval_id"]]["status"] == "pending"

        approve_approval(created["approval_id"])
        raw = json.loads(TEST_APPROVALS_PATH.read_text())
        assert raw[created["approval_id"]]["status"] == "approved"

    def test_15_list_all_includes_decided(self):
        create_approval("eng-1", "nikto", {"target": "10.0.0.1"}, "active_scan", "web", "10.0.0.1")
        req2 = create_approval("eng-1", "gobuster", {"target": "http://x.com"}, "active_scan", "web", "http://x.com")
        approve_approval(req2["approval_id"])
        all_reqs = list_approvals()
        assert len(all_reqs) == 2
        statuses = {r["status"] for r in all_reqs}
        assert statuses == {"pending", "approved"}


class TestExecuteActionApprovalFlow:
    ENG = "test-flow-eng-2"

    @classmethod
    def setup_class(cls):
        _use_test_path()
        scope = storage.load_scope(cls.ENG)
        if scope is None:
            storage.save_scope({
                "engagement_id": cls.ENG,
                "engagement_name": "Flow Test",
                "targets": ["127.0.0.1", "test-target.local"],
                "excluded_targets": [],
                "start_time": "2026-01-01T00:00:00+00:00",
                "end_time": "2030-01-01T00:00:00+00:00",
                "allowed_attack_classes": ["recon", "web", "network"],
                "authorization_contact": {"name": "T", "email": "t@t.com", "role": "t"},
                "emergency_contact": "t",
            })

    @classmethod
    def teardown_class(cls):
        _cleanup_approvals()
        _reset_path()

    def test_passive_tool_auto_executes(self):
        result = execute_action(self.ENG, "nmap", {"target": "127.0.0.1", "ports": "80"})
        assert "error" not in result or result.get("error") is None or "scope" not in result.get("error", "")
        assert "job_id" in result, f"Passive tool should return job_id immediately, got: {result}"
        assert "approval_id" not in result

    def test_active_scan_returns_pending_approval(self):
        result = execute_action(self.ENG, "nikto", {"target": "127.0.0.1", "port": "80"})
        assert "error" not in result
        assert result.get("status") == "pending_approval", f"Expected pending_approval, got: {result}"
        assert "approval_id" in result
        assert result["approval_id"].startswith("apr-")

        fetched = get_approval(result["approval_id"])
        assert fetched is not None
        assert fetched["status"] == "pending"
        assert fetched["tool_name"] == "nikto"

    def test_gobuster_url_returns_pending_approval(self):
        result = execute_action(self.ENG, "gobuster", {
            "target": "http://test-target.local",
            "wordlist": "/usr/share/wordlists/common.txt",
            "mode": "dir",
        })
        assert "error" not in result
        assert result.get("status") == "pending_approval", f"Expected pending_approval, got: {result}"
        assert "approval_id" in result
