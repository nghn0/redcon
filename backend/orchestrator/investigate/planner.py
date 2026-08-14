"""Mission Planner + Investigation Planner.

Mission Planner
    Derives the investigation's top-level objective (and initial unknowns) from
    the engagement goal and the authorised scope the very first time the
    blackboard is created.

Investigation Planner
    Advances the investigation each cycle: recomputes the current phase from
    accumulated evidence, estimates overall confidence that the objective is
    satisfied, and sets the *next objective* — the single most important
    question the investigation should answer right now.

Both are deliberately lightweight: they are deterministic heuristics, the LLM
remains the decision-maker, and they only ever steer (via the blackboard)
rather than execute anything.
"""

from . import blackboard
from .blackboard import (
    PHASE_RECON,
    PHASE_SERVICE_ENUM,
    PHASE_WEB_RECON,
    PHASE_EXPLOITATION,
    PHASE_REPORT,
    PHASES,
    SEVERITY_WEIGHT,
)

NEXT_OBJECTIVE_BY_PHASE = {
    PHASE_RECON: "identify what the scope targets expose: open services, ports and subdomains",
    PHASE_SERVICE_ENUM: "fingerprint the discovered services and prioritise the web/network surface",
    PHASE_WEB_RECON: "map the web application: technologies, paths and known-vulnerability coverage",
    PHASE_EXPLOITATION: "assess whether the confirmed weaknesses are exploitable",
    PHASE_REPORT: "consolidate the evidence into a final assessment",
}

_WEB_HINTS = ("web", "http", "site", "app", "url", "browser", "frontend")
_BRUTE_HINTS = ("brute", "password", "credential", "login", "auth", "hydra", "weak")
_SQL_HINTS = ("sql", "sqli", "injection", "database", "db")


def initialize(session: dict, scope: dict | None = None) -> dict:
    """Ensure a blackboard exists for the session, deriving the objective and
    the first round of unknowns from the goal and the engagement scope."""
    board = blackboard.ensure_blackboard(session)
    if board.get("_initialized"):
        return board

    goal = (session.get("goal") or "").strip()
    if scope is None:
        scope = load_scope(session.get("engagement_id"))
    targets = [t for t in (scope and scope.get("targets") or [])]
    goal_l = goal.lower()

    for host in targets:
        blackboard.add_unknown(board, f"Discover open services on {host}", importance=0.8)
        if "." in host and not host.replace(".", "").isdigit():
            blackboard.add_unknown(
                board, "Enumerate subdomains of the engagement domain", importance=0.7)
        if any(k in goal_l for k in _WEB_HINTS) or any(k in goal_l for k in _SQL_HINTS):
            blackboard.add_unknown(
                board, f"Identify web technologies and applications on {host}", importance=0.9)
            blackboard.add_hypothesis(
                board, f"{host} may run a web application", confidence=0.3,
                support="the engagement goal targets web content",
            )
    if any(k in goal_l for k in _BRUTE_HINTS):
        blackboard.add_unknown(
            board, "Are weak or default credentials in use on exposed services?", importance=0.8)

    board["_initialized"] = True
    board["next_objective"] = NEXT_OBJECTIVE_BY_PHASE.get(board["phase"], "")
    blackboard.touch(board)
    return board


def advance(board: dict, candidates: list | None = None) -> dict:
    """Recompute phase, confidence and next objective from the evidence.

    `candidates` is the freshly generated candidate-action menu for this cycle
    (see orchestrator.engine._investigation_cycle). When it is empty, the
    Knowledge Manager found no valuable work left, which is the signal that
    moves the investigation toward the report phase.
    """
    assets = board.get("assets", [])
    vulns = board.get("potential_vulnerabilities", [])
    hypotheses = board.get("hypotheses", [])
    has_ports = any(a.get("ports") for a in assets)
    has_web = any(
        s.lower() in ("http", "https", "http-alt", "ssl/http")
        for a in assets for s in a.get("services", [])
    )
    has_subdomains = any(a.get("type") == "subdomain" for a in assets)

    # Phase ---------------------------------------------------------------
    strong_weakness = any(
        v.get("severity", "low").lower() in ("high", "critical")
        for v in vulns
    ) or any(
        h.get("status") == "supported" and h.get("confidence", 0) >= 0.8
        for h in hypotheses
        if any(k in h.get("hypothesis", "").lower()
               for k in ("credential", "login", "injection", "exploit"))
    )

    if strong_weakness:
        phase = PHASE_EXPLOITATION
    elif has_web:
        phase = PHASE_WEB_RECON
    elif has_ports or has_subdomains:
        phase = PHASE_SERVICE_ENUM
    else:
        phase = PHASE_RECON

    # Report phase is only reached when the Knowledge Manager found nothing
    # valuable left to run and the picture has some substance; the LLM still
    # decides when to finish.
    if phase != PHASE_EXPLOITATION and not candidates and (
        has_ports or vulns or hypotheses
    ):
        phase = PHASE_REPORT

    if phase != board.get("phase"):
        visited = board.setdefault("phases_visited", [])
        if phase not in visited:
            visited.append(phase)
        board["phase"] = phase

    # Confidence ----------------------------------------------------------
    conf = 0.0
    if has_ports:
        conf += 0.30
    if has_web:
        conf += 0.15
    if has_subdomains:
        conf += 0.10
    if vulns:
        conf += min(0.25, 0.15 + 0.1 * max(SEVERITY_WEIGHT.get(v.get("severity", "info").lower(), 0) for v in vulns))
    if strong_weakness:
        conf += 0.15
    if board.get("completed_actions"):
        conf += min(0.10, 0.02 * len(board["completed_actions"]))
    board["confidence"] = round(min(conf, 0.95), 3)

    board["next_objective"] = NEXT_OBJECTIVE_BY_PHASE.get(phase, "")
    board["reasoning"] = _reasoning_summary(board, candidates or [])
    blackboard.touch(board)
    return board


def _reasoning_summary(board: dict, candidates: list) -> str:
    """One-line justification of the current step, capability-first. Never
    names a tool: it describes WHAT the investigator needs to learn."""
    phase = board.get("phase", PHASE_RECON)
    if candidates:
        top = candidates[0]
        return f"Phase {phase}: to resolve the unknown '{top.get('objective', '')}', request capability {top.get('capability', '')} against {top.get('target', '?')}"
    if board.get("potential_vulnerabilities"):
        return f"Phase {phase}: evidence collected — assess whether the confirmed weaknesses are exploitable"
    if board.get("known_facts"):
        return f"Phase {phase}: no further high-value capability remains — consolidate findings into a report"
    return f"Phase {phase}: no candidate work identified yet — observe next"


def objective_satisfied(board: dict) -> bool:
    """Advisory signal only — the LLM makes the final finish decision."""
    return board.get("confidence", 0) >= 0.8 or board.get("phase") == PHASE_REPORT


def load_scope(engagement_id: str):
    from scope_engine import storage
    try:
        return storage.load_scope(engagement_id)
    except Exception:
        return None