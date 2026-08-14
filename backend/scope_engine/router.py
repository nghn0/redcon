from fastapi import APIRouter, HTTPException
from .models import ScopeFile, ActionRequest, ValidationResult
from .validation import validate as validate_action
from . import storage

router = APIRouter(prefix="/api/scope", tags=["scope"])


@router.post("/engagements", status_code=201)
def create_scope(scope: ScopeFile):
    record = storage.save_scope(scope.model_dump())
    return record


@router.get("/engagements")
def list_engagements():
    return storage.list_engagements()


@router.get("/engagements/{engagement_id}")
def get_scope(engagement_id: str, version: int = None):
    scope = storage.load_scope(engagement_id, version)
    if scope is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return scope


@router.get("/engagements/{engagement_id}/versions")
def get_versions(engagement_id: str):
    return storage.list_versions(engagement_id)


@router.post("/validate", response_model=ValidationResult)
def validate_action_endpoint(action: ActionRequest, engagement_id: str = None):
    eng_id = action.engagement_id if engagement_id is None else engagement_id
    scope = storage.load_scope(eng_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Engagement not found")

    result = validate_action(action.model_dump(), scope)
    return result
