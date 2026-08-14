import ipaddress
from datetime import datetime, timezone
from .models import ALLOWED_ATTACK_CLASSES


def target_in_list(target: str, target_list: list[str]) -> bool:
    for scope_entry in target_list:
        if _matches(scope_entry, target):
            return True
    return False


def _matches(scope_entry: str, action_target: str) -> bool:
    scope_entry = scope_entry.strip()
    action_target = action_target.strip()

    if _try_ip_match(scope_entry, action_target):
        return True

    if _try_domain_match(scope_entry, action_target):
        return True

    return False


def _try_ip_match(scope_entry: str, action_target: str) -> bool:
    try:
        if "/" in scope_entry:
            network = ipaddress.ip_network(scope_entry, strict=False)
            ip = ipaddress.ip_address(action_target)
            return ip in network
        else:
            ip = ipaddress.ip_address(action_target)
            scope_ip = ipaddress.ip_address(scope_entry)
            return ip == scope_ip
    except ValueError:
        return False


def _try_domain_match(scope_entry: str, action_target: str) -> bool:
    import re
    domain_re = re.compile(
        r"^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if not domain_re.match(scope_entry) and not domain_re.match(action_target):
        return False

    scope_entry = scope_entry.lower()
    action_target = action_target.lower()

    if action_target == scope_entry:
        return True

    if scope_entry.startswith("*."):
        parent = scope_entry[2:]
        if action_target == parent or action_target.endswith("." + parent):
            return True

    if action_target.endswith("." + scope_entry):
        return True

    return False


def _ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def validate(action: dict, scope: dict) -> dict:
    target = action["target"]
    attack_class = action["attack_class"]
    timestamp = action["timestamp"]

    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)
    timestamp = _ensure_tz(timestamp)

    targets = scope.get("targets", [])
    excluded = scope.get("excluded_targets", [])

    if target_in_list(target, excluded):
        return {
            "allowed": False,
            "reason": f"Target '{target}' is in the excluded targets list"
        }

    if not target_in_list(target, targets):
        return {
            "allowed": False,
            "reason": f"Target '{target}' is not in the engagement scope"
        }

    start = scope["start_time"]
    end = scope["end_time"]
    if isinstance(start, str):
        start = datetime.fromisoformat(start)
    if isinstance(end, str):
        end = datetime.fromisoformat(end)
    start = _ensure_tz(start)
    end = _ensure_tz(end)

    if timestamp < start or timestamp > end:
        return {
            "allowed": False,
            "reason": (
                f"Action timestamp {timestamp.isoformat()} is outside the "
                f"authorized window ({start.isoformat()} to {end.isoformat()})"
            )
        }

    allowed_classes = scope.get("allowed_attack_classes", [])
    if attack_class not in allowed_classes:
        return {
            "allowed": False,
            "reason": (
                f"Attack class '{attack_class}' is not in the allowed classes: "
                f"{', '.join(allowed_classes)}"
            )
        }

    return {"allowed": True, "reason": "Action is within scope"}
