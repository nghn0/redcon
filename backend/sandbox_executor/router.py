from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from docker.errors import ImageNotFound, DockerException
from docker import from_env as docker_from_env

from .executor import (
    execute_action,
    SandboxExecutor,
    ensure_image_built,
    build_image_async,
    get_build_status,
    IMAGE_NAME,
)

router = APIRouter(prefix="/api", tags=["sandbox"])


class ExecuteRequest(BaseModel):
    engagement_id: str
    tool_name: str
    params: dict


class ExecuteResponse(BaseModel):
    job_id: str | None = None
    error: str | None = None
    status: str | None = None
    approval_id: str | None = None


class JobStatusResponse(BaseModel):
    job_id: str
    engagement_id: str | None = None
    status: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    findings: dict | None = None
    output_file: str | None = None
    command: list[str] | None = None
    started_at: str | None = None
    finished_at: str | None = None


class BuildStatusResponse(BaseModel):
    build_job_id: str
    status: str
    logs: list[str] = []
    error: str | None = None
    image: str = IMAGE_NAME
    started_at: str | None = None
    finished_at: str | None = None


@router.post("/execute")
def execute(req: ExecuteRequest) -> ExecuteResponse:
    result = execute_action(req.engagement_id, req.tool_name, req.params)
    if "error" in result:
        raise HTTPException(status_code=403, detail=result["error"])
    if result.get("status") == "pending_approval":
        return ExecuteResponse(
            status="pending_approval",
            approval_id=result["approval_id"],
        )
    return ExecuteResponse(job_id=result["job_id"])


@router.get("/execute/image-status")
def image_status():
    try:
        docker_from_env().images.get(IMAGE_NAME)
        return {"status": "ready", "image": IMAGE_NAME}
    except ImageNotFound:
        return {"status": "not_found", "image": IMAGE_NAME}
    except DockerException:
        return {"status": "not_found", "image": IMAGE_NAME, "detail": "Docker daemon not reachable"}


@router.post("/execute/build-image")
def build_image() -> BuildStatusResponse:
    """Start async image build. Returns build_job_id immediately for status polling."""
    build_job_id = build_image_async()
    return BuildStatusResponse(
        build_job_id=build_job_id,
        status="building",
        image=IMAGE_NAME,
        started_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/execute/build-status/{build_job_id}")
def build_status(build_job_id: str) -> BuildStatusResponse:
    result = get_build_status(build_job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Build job not found")
    return BuildStatusResponse(
        build_job_id=result["build_job_id"],
        status=result["status"],
        logs=result.get("logs", []),
        error=result.get("error"),
        image=result.get("image", IMAGE_NAME),
        started_at=result.get("started_at"),
        finished_at=result.get("finished_at"),
    )


@router.get("/execute/{job_id}")
def get_job_status(job_id: str) -> JobStatusResponse:
    result = SandboxExecutor.get_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(**result)
