from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator
import ipaddress
import re

ALLOWED_ATTACK_CLASSES = {"recon", "web", "network", "exploitation", "social_eng", "mitm"}


class AuthorizationContact(BaseModel):
    name: str
    email: str
    role: str


class ScopeFile(BaseModel):
    engagement_id: str
    engagement_name: str
    version: int = 1
    targets: list[str]
    excluded_targets: list[str] = []
    start_time: datetime
    end_time: datetime
    allowed_attack_classes: list[str]
    authorization_contact: AuthorizationContact
    emergency_contact: str
    rate_limit: Optional[int] = None
    notify_before_exploit: Optional[bool] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("targets", "excluded_targets")
    @classmethod
    def validate_targets(cls, v):
        for t in v:
            if not is_valid_target(t):
                raise ValueError(f"Invalid target format: {t}")
        return v

    @field_validator("allowed_attack_classes")
    @classmethod
    def validate_attack_classes(cls, v):
        if not v:
            raise ValueError("At least one attack class must be selected")
        invalid = set(v) - ALLOWED_ATTACK_CLASSES
        if invalid:
            raise ValueError(f"Invalid attack classes: {invalid}")
        return v

    @field_validator("end_time")
    @classmethod
    def validate_end_after_start(cls, v, info):
        if "start_time" in info.data and v <= info.data["start_time"]:
            raise ValueError("end_time must be after start_time")
        return v


class ActionRequest(BaseModel):
    engagement_id: str
    target: str
    attack_class: str
    timestamp: datetime


class ValidationResult(BaseModel):
    allowed: bool
    reason: str


DOMAIN_PATTERN = re.compile(
    r"^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_valid_target(target: str) -> bool:
    target = target.strip()

    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
            return True
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    if DOMAIN_PATTERN.match(target):
        return True

    return False
