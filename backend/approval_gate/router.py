from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from .gate import (
    create_approval,
    get_approval,
    list_approvals,
    approve_approval,
    deny_approval,
    set_approval_job_id,
    APPROVAL_EXPIRY_MINUTES,
)
from tool_registry.registry import get_tool, build_command, ToolRegistryError
from scope_engine import storage as scope_storage
from scope_engine.validation import validate as validate_action
from sandbox_executor.executor import SandboxExecutor, ExecutorError, _extract_host
from docker.errors import DockerException, ImageNotFound

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


class ApprovalResponse(BaseModel):
    approval_id: str
    engagement_id: str
    tool_name: str
    params: dict
    risk_tier: str
    attack_class: str
    target: str
    requested_at: str
    status: str
    decided_by: str | None = None
    decided_at: str | None = None
    deny_reason: str | None = None
    result_job_id: str | None = None


class ApproveResponse(BaseModel):
    status: str
    job_id: str | None = None
    approval_id: str


class DenyRequest(BaseModel):
    reason: str = ""
    decided_by: str = "ui-user"


@router.get("")
def list_all_approvals(
    engagement_id: str | None = Query(None),
    include_decided: bool = Query(False),
) -> list[ApprovalResponse]:
    records = list_approvals(engagement_id)
    if not include_decided:
        records = [r for r in records if r["status"] == "pending"]
    return [ApprovalResponse(**r) for r in records]


@router.get("/{approval_id}")
def get_approval_detail(approval_id: str) -> ApprovalResponse:
    record = get_approval(approval_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return ApprovalResponse(**record)


@router.post("/{approval_id}/approve")
def approve_and_execute(approval_id: str) -> ApproveResponse:
    record = get_approval(approval_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Approval request not found")

    if record["status"] == "expired":
        raise HTTPException(status_code=400, detail="Approval request has expired — submit a new action")
    if record["status"] != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Approval request is already {record['status']} — cannot approve"
        )

    engagement_id = record["engagement_id"]
    tool_name = record["tool_name"]
    params = record["params"]

    scope = scope_storage.load_scope(engagement_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Engagement not found — scope may have been deleted")

    try:
        tool = get_tool(tool_name)
    except ToolRegistryError as e:
        raise HTTPException(status_code=400, detail=str(e))

    attack_class = tool.get("attack_class")
    target = params.get("target", "")
    scope_target = _extract_host(target)

    action = {
        "engagement_id": engagement_id,
        "target": scope_target,
        "attack_class": attack_class,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    validation = validate_action(action, scope)
    if not validation["allowed"]:
        raise HTTPException(status_code=403, detail=f"Scope validation failed at time of approval: {validation['reason']}")

    try:
        command = build_command(tool_name, params)
    except ToolRegistryError as e:
        raise HTTPException(status_code=400, detail=str(e))

    egress_restricted = tool.get("egress_restricted", True)
    try:
        updated = approve_approval(approval_id)
        if updated is None:
            raise HTTPException(status_code=400, detail="Approval request is no longer pending")

        job_id = SandboxExecutor.run(
            engagement_id=engagement_id,
            command=command,
            tool_name=tool_name,
            egress_restricted=egress_restricted,
        )
        set_approval_job_id(approval_id, job_id)
        return ApproveResponse(status="approved", job_id=job_id, approval_id=approval_id)
    except (ExecutorError, DockerException, ImageNotFound) as e:
        raise HTTPException(status_code=500, detail=f"Execution failed after approval: {e}")


@router.post("/{approval_id}/deny")
def deny_approval_endpoint(approval_id: str, body: DenyRequest = DenyRequest()) -> ApprovalResponse:
    updated = deny_approval(approval_id, decided_by=body.decided_by, reason=body.reason)
    if updated is None:
        raise HTTPException(status_code=400, detail="Approval request not found or is no longer pending")
    return ApprovalResponse(**updated)
