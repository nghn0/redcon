import json
import threading
from datetime import datetime, timezone
from pathlib import Path

SESSIONS_DIR = Path(__file__).parent.parent / "data" / "sessions"
_session_lock = threading.Lock()
_session_counter = 0


def _next_session_id() -> str:
    global _session_counter
    with _session_lock:
        # The counter is in-memory and resets on server restart; never reuse an
        # id that already exists on disk or the new session would silently
        # overwrite a previous session.
        while True:
            _session_counter += 1
            candidate = f"orch-{_session_counter:04d}"
            if not _session_path(candidate).exists():
                return candidate


def _session_path(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.json"


def _ensure_dir():
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def create_session(engagement_id: str, goal: str) -> dict:
    _ensure_dir()
    session_id = _next_session_id()
    now = datetime.now(timezone.utc).isoformat()
    session = {
        "session_id": session_id,
        "engagement_id": engagement_id,
        "goal": goal,
        "created_at": now,
        "updated_at": now,
        "status": "active",
        "findings_so_far": [],
        "tools_already_run": [],
        "pending_or_denied": [],
        "action_history": [],
        # Investigation blackboard — lazily initialized on the first
        # orchestrator step (see orchestrator.investigate).
        "investigation": None,
    }
    save_session(session)
    return session


def save_session(session: dict):
    _ensure_dir()
    session["updated_at"] = datetime.now(timezone.utc).isoformat()
    path = _session_path(session["session_id"])
    with _session_lock:
        path.write_text(json.dumps(session, indent=2, default=str))


def load_session(session_id: str) -> dict | None:
    path = _session_path(session_id)
    try:
        with _session_lock:
            return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def list_sessions() -> list[dict]:
    _ensure_dir()
    sessions = []
    for path in sorted(SESSIONS_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text())
            sessions.append({
                "session_id": data.get("session_id"),
                "engagement_id": data.get("engagement_id"),
                "goal": data.get("goal", "")[:80],
                "status": data.get("status"),
                "created_at": data.get("created_at"),
                "updated_at": data.get("updated_at"),
                "action_count": len(data.get("action_history", [])),
                "finding_count": len(data.get("findings_so_far", [])),
            })
        except (json.JSONDecodeError, KeyError):
            pass
    return sessions
