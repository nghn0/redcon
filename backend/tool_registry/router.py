from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from .registry import (
    get_all_tools,
    get_tool,
    build_command,
    is_tool_installed,
    install_tool,
    delete_tool,
    run_tool,
    get_run_result,
    ToolRegistryError,
    UnknownToolError,
    SafeTargetRestrictionError,
)

router = APIRouter(prefix="/api/tools", tags=["tools"])


class BuildCommandRequest(BaseModel):
    tool_name: str
    params: dict


class RunRequest(BaseModel):
    tool_name: str
    params: dict


@router.get("")
def list_tools():
    tools = get_all_tools()
    result = []
    for t in tools:
        entry = dict(t)
        entry["installed"] = is_tool_installed(t["name"])
        result.append(entry)
    return result


@router.get("/{tool_name}")
def get_tool_detail(tool_name: str):
    try:
        tool = get_tool(tool_name)
        tool["installed"] = is_tool_installed(tool_name)
        return tool
    except UnknownToolError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/build-command")
def build_command_endpoint(req: BuildCommandRequest):
    try:
        cmd = build_command(req.tool_name, req.params)
        return {"tool_name": req.tool_name, "command": cmd}
    except ToolRegistryError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{tool_name}/install")
def install_tool_endpoint(tool_name: str):
    try:
        result = install_tool(tool_name)
        return result
    except UnknownToolError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{tool_name}/delete")
def delete_tool_endpoint(tool_name: str):
    try:
        result = delete_tool(tool_name)
        return result
    except UnknownToolError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/run")
def run_tool_endpoint(req: RunRequest):
    try:
        job_id = run_tool(req.tool_name, req.params)
        return {"job_id": job_id}
    except SafeTargetRestrictionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ToolRegistryError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/run/{job_id}")
def get_run_result_endpoint(job_id: str):
    result = get_run_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return result
