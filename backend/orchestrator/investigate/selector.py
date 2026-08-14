"""Action Selector.

Turns the Knowledge Manager's candidate menu into a ranked shortlist by scoring
every candidate with the same heuristics a lead tester applies implicitly:

    score =
        + 0.40 * expected information gain
        + 0.25 * likelihood of useful findings
        + 0.15 * fit with the current investigation phase
        - 0.10 * execution cost
        - 0.10 * execution risk

Weights favour learning the most about the biggest unknown at the lowest cost
and risk. The ranked result is written back to the blackboard as
`action_scores` (with a rationale per candidate) and surfaced to the LLM, which
makes the final decision — the selector only advises.
"""

from . import blackboard
from tool_registry import capability_catalog as catalog

_W_GAIN = 0.40
_W_LIKELIHOOD = 0.25
_W_PHASE = 0.15
_W_COST = 0.10
_W_RISK = 0.10

# phase 0..1 fit factor per candidate phase vs the board phase.
_PHASE_FIT = 1.0


def _phase_fit(candidate_phase: str, board_phase: str) -> float:
    from .blackboard import PHASES
    try:
        c_idx = PHASES.index(candidate_phase)
        b_idx = PHASES.index(board_phase)
    except ValueError:
        return 0.5
    # Candidates from an earlier phase get partial credit (harmless prep), later
    # phases require the board to have caught up.
    if c_idx <= b_idx:
        return _PHASE_FIT
    return max(0.0, 1.0 - (c_idx - b_idx) * 0.45)


def _score(candidate: dict, board_phase: str) -> dict:
    info_gain = candidate.get("info_gain", 0.5)
    likelihood = candidate.get("likelihood", 0.5)
    cost = candidate.get("cost", 0.3)
    risk = candidate.get("risk", 0.5)
    phase = _phase_fit(candidate.get("phase", ""), board_phase)

    score = (
        _W_GAIN * info_gain
        + _W_LIKELIHOOD * likelihood
        + _W_PHASE * phase
        - _W_COST * cost
        - _W_RISK * risk
    )
    score = round(max(0.0, min(1.0, score)), 3)

    parts = [
        f"+{_W_GAIN:.2f}*gain {info_gain:.2f}",
        f"+{_W_LIKELIHOOD:.2f}*likelihood {likelihood:.2f}",
        f"+{_W_PHASE:.2f}*phase_fit {phase:.2f}",
        f"-{_W_COST:.2f}*cost {cost:.2f}",
        f"-{_W_RISK:.2f}*risk {risk:.2f}",
    ]
    return {"score": score, "score_breakdown": parts}


def rank(candidates: list[dict], board: dict, limit: int = 6) -> list[dict]:
    """Score + sort candidates, persist `action_scores` on the blackboard."""
    board_phase = board.get("phase", blackboard.PHASE_RECON)
    scored = []
    for c in candidates:
        s = _score(c, board_phase)
        scored.append({
            **c,
            "score": s["score"],
            "score_breakdown": s["score_breakdown"],
        })
    scored.sort(key=lambda c: -c["score"])

    # Persist only the shortlist with rationale; the LLM sees these.
    board["action_scores"] = [
        {
            "capability": c.get("capability") or c.get("tool_name"),
            "capability_description": catalog.describe(c.get("capability") or c.get("tool_name") or ""),
            "target": c["target"],
            "params": c["params"],
            "objective": c["objective"],
            "info_gain": c["info_gain"],
            "cost": c["cost"],
            "risk": c["risk"],
            "likelihood": c["likelihood"],
            "score": c["score"],
            "rationale": c.get("rationale") or c.get("note", ""),
        }
        for c in scored[:limit]
    ]
    blackboard.set_capabilities_remaining(board, [c.get("capability") or c.get("tool_name") for c in scored[:limit]])
    blackboard.touch(board)
    return board["action_scores"]
