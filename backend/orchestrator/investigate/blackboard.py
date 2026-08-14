"""Investigation blackboard.

The shared memory of the investigation loop. Every reasoning component
(Mission Planner, Investigation Planner, Evidence Analyzer, Knowledge Manager,
Action Selector) reads from it; every completed tool execution writes to it via
the Evidence Analyzer. Persisted inside the session dict under "investigation".

The blackboard is deliberately plain-data (dicts/lists of primitives) so it
serialises cleanly into JSON session files and into the compact LLM context.
"""

import re
from datetime import datetime, timezone
from typing import Any

# Interesting-service knowledge lives with the parsers (Phase 2); the
# investigation loop (Phase 5) depends on the tool layer, not vice-versa.
from tool_registry.parsers.enrich import INTERESTING_SERVICES

PHASE_RECON = "recon"
PHASE_SERVICE_ENUM = "service_enum"
PHASE_WEB_RECON = "web_recon"
PHASE_EXPLOITATION = "exploitation"
PHASE_REPORT = "report"

PHASES = [
    PHASE_RECON,
    PHASE_SERVICE_ENUM,
    PHASE_WEB_RECON,
    PHASE_EXPLOITATION,
    PHASE_REPORT,
]

# Severity -> confidence in the finding being genuine + interestingness.
SEVERITY_CONFIDENCE = {
    "critical": 0.95,
    "high": 0.85,
    "medium": 0.7,
    "low": 0.55,
    "info": 0.4,
}
SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.05,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(text: str, limit: int = 24) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:limit] or "item"


def empty_blackboard(objective: str = "") -> dict:
    """A fresh investigation board for a new session."""
    return {
        "objective": objective,
        "phase": PHASE_RECON,
        "phases_visited": [PHASE_RECON],
        "known_facts": [],
        "hypotheses": [],
        "unknowns": [],
        "assets": [],
        "interesting_assets": [],
        "interesting_ports": [],
        "interesting_services": [],
        "interesting_paths": [],
        "interesting_findings": [],
        "potential_vulnerabilities": [],
        "completed_actions": [],
        "failed_actions": [],
        "dead_ends": [],
        "completed_tasks": [],
        "capabilities_used": [],
        "capabilities_remaining": [],
        "pending_approvals": [],
        "confidence": 0.0,
        "next_objective": "",
        "reasoning": "",
        "action_scores": [],
        # Internal bookkeeping (not surfaced to the LLM/UI as guidance).
        "_processed_jobs": [],
        "updated_at": _now(),
    }


def ensure_blackboard(session: dict, objective: str = "") -> dict:
    """Create the blackboard on first use; otherwise return the existing one."""
    board = session.get("investigation")
    if not isinstance(board, dict):
        board = empty_blackboard(objective or _default_objective(session))
        session["investigation"] = board
    return board


def _default_objective(session: dict) -> str:
    goal = (session.get("goal") or "").strip()
    if goal:
        return goal
    return "Assess the security posture of the authorized engagement targets."


def add_fact(board: dict, fact: str, *, source: str, target: str,
             confidence: float, evidence: str, signature: str | None = None) -> None:
    entries = board.setdefault("known_facts", [])
    sig = signature or _slug(f"{source}-{target}-{fact}")
    for e in entries:
        if e.get("_sig") == sig:
            return
    entries.append({
        "_sig": sig,
        "fact": fact,
        "source": source,
        "target": target,
        "confidence": round(min(max(confidence, 0.0), 1.0), 3),
        "evidence": evidence,
        "timestamp": _now(),
    })


def add_hypothesis(board: dict, hypothesis: str, *, confidence: float,
                   support: str = "") -> None:
    entries = board.setdefault("hypotheses", [])
    sig = _slug(hypothesis)
    for h in entries:
        if h.get("_sig") == sig:
            h["confidence"] = round(max(h.get("confidence", 0.0), confidence), 3)
            if support and support not in h.get("evidence_for", []):
                h["evidence_for"].append(support)
            if h["confidence"] >= 0.7:
                h["status"] = "supported"
            return
    entries.append({
        "_sig": sig,
        "hypothesis": hypothesis,
        "status": "supported" if confidence >= 0.7 else "active",
        "confidence": round(min(max(confidence, 0.0), 1.0), 3),
        "evidence_for": [support] if support else [],
        "evidence_against": [],
        "timestamp": _now(),
    })


def refute_hypothesis(board: dict, hypothesis: str, reason: str = "") -> None:
    entries = board.setdefault("hypotheses", [])
    sig = _slug(hypothesis)
    for h in entries:
        if h.get("_sig") == sig:
            h["status"] = "refuted"
            h["confidence"] = 0.0
            if reason:
                h["evidence_against"].append(reason)
            return


def add_unknown(board: dict, question: str, *, importance: float = 0.5) -> bool:
    """Register an open question. Returns True if newly added."""
    entries = board.setdefault("unknowns", [])
    sig = _slug(question)
    for u in entries:
        if u.get("_sig") == sig:
            return False
    entries.append({
        "_sig": sig,
        "question": question,
        "importance": round(min(max(importance, 0.0), 1.0), 2),
        "status": "open",
        "answered_by": None,
        "timestamp": _now(),
    })
    return True


def answer_unknown(board: dict, question: str, *, source: str) -> None:
    entries = board.setdefault("unknowns", [])
    sig = _slug(question)
    for u in entries:
        if u.get("_sig") == sig and u.get("status") == "open":
            u["status"] = "answered"
            u["answered_by"] = source
            return


def _find_asset(board: dict, target: str) -> dict | None:
    normalized = str(target).strip().lower()
    for a in board.setdefault("assets", []):
        if str(a.get("target", "")).strip().lower() == normalized:
            return a
    return None


def ensure_asset(board: dict, target: str, *, asset_type: str = "host",
                 parent: str | None = None) -> dict:
    asset = _find_asset(board, target)
    if asset is None:
        asset = {
            "target": str(target).strip(),
            "type": asset_type,
            "ports": [],
            "services": [],
            "paths": [],
            "parent": parent,
            "interesting": False,
            "confidence": 0.5,
            "last_seen": _now(),
        }
        board.setdefault("assets", []).append(asset)
        if asset_type != "host":
            board.setdefault("interesting_assets", [])
            if asset["target"] not in board["interesting_assets"]:
                board["interesting_assets"].append(asset["target"])
    else:
        asset["last_seen"] = _now()
    return asset


def _push_unique(lst: list, value: Any) -> None:
    if value not in lst:
        lst.append(value)


def note_service_asset(board: dict, target: str, port, service: str,
                       *, is_interesting: bool) -> None:
    asset = ensure_asset(board, target)
    port = int(port) if isinstance(port, (int, str)) and str(port).isdigit() else port
    if port not in asset["ports"]:
        asset["ports"].append(port)
    if service and service not in asset["services"]:
        asset["services"].append(service)
    if is_interesting:
        asset["interesting"] = True
        interesting_ports = board.setdefault("interesting_ports", [])
        if port not in interesting_ports:
            interesting_ports.append(port)
        interesting_services = board.setdefault("interesting_services", [])
        if service not in interesting_services:
            interesting_services.append(service)
        interesting_assets = board.setdefault("interesting_assets", [])
        if asset["target"] not in interesting_assets:
            interesting_assets.append(asset["target"])


def note_path_asset(board: dict, target: str, path: str, *, interesting: bool) -> None:
    asset = ensure_asset(board, target)
    if path not in asset["paths"]:
        asset["paths"].append(path)
    if interesting:
        interesting_paths = board.setdefault("interesting_paths", [])
        if path not in interesting_paths:
            interesting_paths.append(path)


def add_potential_vulnerability(board: dict, *, name: str, severity: str,
                                target: str, path: str | None = None,
                                confidence: float | None = None, source: str = "") -> None:
    entries = board.setdefault("potential_vulnerabilities", [])
    sig = _slug(f"{name}-{target}-{path or ''}")
    for v in entries:
        if v.get("_sig") == sig:
            return
    conf = confidence if confidence is not None else SEVERITY_CONFIDENCE.get(severity.lower(), 0.5)
    entries.append({
        "_sig": sig,
        "name": name,
        "severity": severity,
        "target": target,
        "path": path,
        "confidence": round(min(max(conf, 0.0), 1.0), 3),
        "status": "suspected",
        "source": source,
        "timestamp": _now(),
    })


def mark_completed_action(board: dict, action: str) -> None:
    _push_unique(board.setdefault("completed_actions", []), action)


def mark_failed_action(board: dict, action: str) -> None:
    _push_unique(board.setdefault("failed_actions", []), action)


def mark_capability_used(board: dict, capability: str) -> None:
    """Record that a capability has been exercised. Deduped."""
    if capability:
        used = board.setdefault("capabilities_used", [])
        if capability not in used:
            used.append(capability)
        _prune_capabilities_remaining(board)


def set_capabilities_remaining(board: dict, capabilities: list[str]) -> None:
    board["capabilities_remaining"] = sorted({
        c for c in (capabilities or []) if c not in board.get("capabilities_used", [])
    })


def _prune_capabilities_remaining(board: dict) -> None:
    used = set(board.get("capabilities_used", []))
    board["capabilities_remaining"] = [
        c for c in board.get("capabilities_remaining", [])
        if c not in used
    ]


def add_dead_end(board: dict, capability: str, reason: str = "") -> None:
    """Capabilities that produced nothing / were refuted. Deduped per cap."""
    dead = board.setdefault("dead_ends", [])
    for d in dead:
        if d.get("capability") == capability:
            if reason and reason not in d.get("reasons", []):
                d.setdefault("reasons", []).append(reason)
            return
    dead.append({"capability": capability, "reasons": [reason] if reason else [], "timestamp": _now()})


def add_interesting_finding(board: dict, finding: dict) -> None:
    """Track high-value findings for the final report / LLM context."""
    if not isinstance(finding, dict):
        return
    key = _slug(f"{finding.get('type','')}-{finding.get('_sig','')}"
                f"-{finding.get('detail', {}).get('name', finding.get('detail', {}).get('path', ''))}")
    lst = board.setdefault("interesting_findings", [])
    for f in lst:
        if f.get("_sig") == key:
            return
    item = dict(finding)
    item["_sig"] = key
    lst.append(item)


def mark_completed_task(board: dict, objective: str) -> None:
    """Discrete investigation objectives that have been substantially satisfied."""
    if objective:
        _push_unique(board.setdefault("completed_tasks", []), objective)


def add_pending_approval(board: dict, approval_id: str) -> None:
    _push_unique(board.setdefault("pending_approvals", []), approval_id)


def resolve_pending_approval(board: dict, approval_id: str) -> None:
    board.setdefault("pending_approvals", [])
    if approval_id in board["pending_approvals"]:
        board["pending_approvals"].remove(approval_id)


def is_action_done(board: dict, action: str) -> bool:
    return action in board.setdefault("completed_actions", []) or \
        action in board.setdefault("failed_actions", [])


def touch(board: dict) -> None:
    board["updated_at"] = _now()


def open_unknowns(board: dict) -> list[dict]:
    return [
        u for u in board.setdefault("unknowns", [])
        if u.get("status") == "open"
    ]