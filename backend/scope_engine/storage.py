import os
import json
from datetime import datetime
from typing import Optional

SCOPES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scopes")


def _engagement_dir(engagement_id: str) -> str:
    return os.path.join(SCOPES_DIR, engagement_id)


def _scope_path(engagement_id: str, version: int) -> str:
    return os.path.join(_engagement_dir(engagement_id), f"scope_v{version}.json")


def save_scope(scope: dict) -> dict:
    engagement_id = scope["engagement_id"]
    eng_dir = _engagement_dir(engagement_id)
    os.makedirs(eng_dir, exist_ok=True)

    existing = list_versions(engagement_id)
    version = len(existing) + 1

    record = {**scope, "version": version, "created_at": datetime.utcnow().isoformat()}

    for dt_field in ["start_time", "end_time"]:
        if isinstance(record.get(dt_field), datetime):
            record[dt_field] = record[dt_field].isoformat()

    path = _scope_path(engagement_id, version)
    with open(path, "w") as f:
        json.dump(record, f, indent=2, default=str)

    return record


def load_scope(engagement_id: str, version: Optional[int] = None) -> Optional[dict]:
    versions = list_versions(engagement_id)
    if not versions:
        return None

    if version is None:
        version = max(v["version"] for v in versions)

    path = _scope_path(engagement_id, version)
    if not os.path.exists(path):
        return None

    with open(path) as f:
        return json.load(f)


def list_versions(engagement_id: str) -> list[dict]:
    eng_dir = _engagement_dir(engagement_id)
    if not os.path.isdir(eng_dir):
        return []

    versions = []
    for fname in os.listdir(eng_dir):
        if fname.startswith("scope_v") and fname.endswith(".json"):
            try:
                v = int(fname.replace("scope_v", "").replace(".json", ""))
                path = os.path.join(eng_dir, fname)
                mtime = os.path.getmtime(path)
                versions.append({"version": v, "file": fname, "created_at": mtime})
            except ValueError:
                continue

    versions.sort(key=lambda x: x["version"])
    return versions


def list_engagements() -> list[dict]:
    if not os.path.isdir(SCOPES_DIR):
        return []

    engagements = []
    for name in os.listdir(SCOPES_DIR):
        eng_dir = os.path.join(SCOPES_DIR, name)
        if os.path.isdir(eng_dir):
            scope = load_scope(name)
            if scope:
                engagements.append({
                    "engagement_id": scope["engagement_id"],
                    "engagement_name": scope["engagement_name"],
                    "version": scope["version"],
                    "start_time": scope.get("start_time"),
                    "end_time": scope.get("end_time"),
                })
    return engagements
