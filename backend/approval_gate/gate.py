import json
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

APPROVALS_PATH = Path(__file__).parent.parent / "data" / "approvals.json"
APPROVAL_EXPIRY_MINUTES = 30

_approvals: dict[str, dict] = {}
_approvals_lock = threading.RLock()
_approval_counter = 0


def _load_approvals() -> dict[str, dict]:
    try:
        return json.loads(APPROVALS_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_approvals(data: dict[str, dict]) -> None:
    APPROVALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    APPROVALS_PATH.write_text(json.dumps(data, indent=2, default=str))


def _get_next_approval_id() -> str:
    global _approval_counter
    with _approvals_lock:
        _approval_counter += 1
        return f"apr-{_approval_counter:04d}"


def _is_expired(requested_at_str: str) -> bool:
    try:
        requested = datetime.fromisoformat(requested_at_str)
        if requested.tzinfo is None:
            requested = requested.replace(tzinfo=timezone.utc)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=APPROVAL_EXPIRY_MINUTES)
        return requested < cutoff
    except (ValueError, TypeError):
        return False


def create_approval(
    engagement_id: str,
    tool_name: str,
    params: dict,
    risk_tier: str,
    attack_class: str,
    target: str,
) -> dict:
    with _approvals_lock:
        stored = _load_approvals()
        approval_id = _get_next_approval_id()
        now = datetime.now(timezone.utc)
        record = {
            "approval_id": approval_id,
            "engagement_id": engagement_id,
            "tool_name": tool_name,
            "params": params,
            "risk_tier": risk_tier,
            "attack_class": attack_class,
            "target": target,
            "requested_at": now.isoformat(),
            "status": "pending",
            "decided_by": None,
            "decided_at": None,
            "deny_reason": None,
            "result_job_id": None,
        }
        stored[approval_id] = record
        _save_approvals(stored)
        _approvals[approval_id] = dict(record)
        return record


def get_approval(approval_id: str) -> dict | None:
    with _approvals_lock:
        stored = _load_approvals()
        record = stored.get(approval_id)
        if record is None:
            record = _approvals.get(approval_id)
        if record is None:
            return None
        if record["status"] == "pending" and _is_expired(record["requested_at"]):
            record["status"] = "expired"
            stored[approval_id] = record
            _approvals[approval_id] = record
            _save_approvals(stored)
        return dict(record)


def list_approvals(engagement_id: str | None = None) -> list[dict]:
    with _approvals_lock:
        stored = _load_approvals()
        results = []
        for record in stored.values():
            if record["status"] == "pending" and _is_expired(record["requested_at"]):
                record["status"] = "expired"
                stored[record["approval_id"]] = record
            if engagement_id is None or record.get("engagement_id") == engagement_id:
                results.append(dict(record))
        _save_approvals(stored)
        results.sort(key=lambda r: r.get("requested_at", ""), reverse=True)
        return results


def approve_approval(approval_id: str, decided_by: str = "ui-user") -> dict | None:
    with _approvals_lock:
        stored = _load_approvals()
        record = stored.get(approval_id) or _approvals.get(approval_id)
        if record is None:
            return None
        if _is_expired(record["requested_at"]):
            record["status"] = "expired"
            stored[approval_id] = record
            _approvals[approval_id] = record
            _save_approvals(stored)
            return None
        if record["status"] != "pending":
            return None
        now = datetime.now(timezone.utc)
        record["status"] = "approved"
        record["decided_by"] = decided_by
        record["decided_at"] = now.isoformat()
        stored[approval_id] = record
        _approvals[approval_id] = record
        _save_approvals(stored)
        return dict(record)


def deny_approval(approval_id: str, decided_by: str = "ui-user", reason: str = "") -> dict | None:
    with _approvals_lock:
        stored = _load_approvals()
        record = stored.get(approval_id) or _approvals.get(approval_id)
        if record is None:
            return None
        if record["status"] != "pending":
            return None
        now = datetime.now(timezone.utc)
        record["status"] = "denied"
        record["decided_by"] = decided_by
        record["decided_at"] = now.isoformat()
        record["deny_reason"] = reason
        stored[approval_id] = record
        _approvals[approval_id] = record
        _save_approvals(stored)
        return dict(record)


def set_approval_job_id(approval_id: str, job_id: str) -> None:
    with _approvals_lock:
        stored = _load_approvals()
        record = stored.get(approval_id)
        if record is not None:
            record["result_job_id"] = job_id
            stored[approval_id] = record
            _approvals[approval_id] = record
            _save_approvals(stored)
