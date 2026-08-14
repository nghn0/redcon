from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .state import create_session, load_session, list_sessions, save_session
from .engine import (
    orchestrator_step,
    resolve_pending_approvals,
    confirm_params,
    cancel_params,
)
from .llm_client import check_llm_health

router = APIRouter(prefix="/api/orchestrator", tags=["orchestrator"])


class CreateSessionRequest(BaseModel):
    engagement_id: str
    goal: str = ""


class MessageRequest(BaseModel):
    message: str


class ParamConfirmRequest(BaseModel):
    params: dict


class SessionStateResponse(BaseModel):
    session_id: str
    engagement_id: str
    goal: str
    status: str
    summary: str | None = None
    findings_so_far: list = []
    tools_already_run: list[str] = []
    action_history: list = []
    pending_or_denied: list = []
    pending_param_confirm: dict | None = None
    investigation: dict | None = None
    created_at: str | None = None
    updated_at: str | None = None


class SessionSummary(BaseModel):
    session_id: str
    engagement_id: str
    goal: str
    status: str
    created_at: str | None = None
    updated_at: str | None = None
    action_count: int = 0
    finding_count: int = 0


@router.post("/sessions", status_code=201, response_model=SessionStateResponse)
def create_session_endpoint(req: CreateSessionRequest):
    session = create_session(req.engagement_id, req.goal)
    result = orchestrator_step(session["session_id"], user_message=req.goal if req.goal else None)
    return SessionStateResponse(**result)


@router.post("/sessions/{session_id}/message", response_model=SessionStateResponse)
def send_message(session_id: str, req: MessageRequest):
    result = orchestrator_step(session_id, user_message=req.message)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return SessionStateResponse(**result)


@router.post("/sessions/{session_id}/params-confirm", response_model=SessionStateResponse)
def confirm_params_endpoint(session_id: str, req: ParamConfirmRequest):
    """User accepted (and possibly overrode) the parked tool params. Execute."""
    result = confirm_params(session_id, req.params)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return SessionStateResponse(**result)


@router.post("/sessions/{session_id}/params-cancel", response_model=SessionStateResponse)
def cancel_params_endpoint(session_id: str):
    """User dismissed the parked action. Nothing executes."""
    result = cancel_params(session_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return SessionStateResponse(**result)


@router.get("/sessions/{session_id}", response_model=SessionStateResponse)
def get_session(session_id: str):
    result = resolve_pending_approvals(session_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return SessionStateResponse(**result)


@router.get("/health")
def llm_health():
    return check_llm_health()


@router.get("/sessions", response_model=list[SessionSummary])
def list_all_sessions():
    return [SessionSummary(**s) for s in list_sessions()]
