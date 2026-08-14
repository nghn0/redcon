import pytest
from datetime import datetime, timedelta
from scope_engine.validation import validate, target_in_list, _matches
from scope_engine.models import is_valid_target, ALLOWED_ATTACK_CLASSES


SCOPE = {
    "engagement_id": "eng-001",
    "engagement_name": "Test Engagement",
    "version": 1,
    "targets": [
        "203.0.113.0/24",
        "example.com",
        "192.168.1.100",
    ],
    "excluded_targets": [
        "203.0.113.50",
        "admin.example.com",
    ],
    "start_time": datetime(2025, 1, 1, 0, 0, 0).isoformat(),
    "end_time": datetime(2025, 12, 31, 23, 59, 59).isoformat(),
    "allowed_attack_classes": ["recon", "web", "network"],
    "authorization_contact": {
        "name": "Alice",
        "email": "alice@example.com",
        "role": "CISO"
    },
    "emergency_contact": "Bob (bob@example.com)",
    "rate_limit": None,
    "notify_before_exploit": None,
}


def test_a_in_scope_target_valid_time_allowed_class():
    action = {
        "engagement_id": "eng-001",
        "target": "203.0.113.10",
        "attack_class": "recon",
        "timestamp": datetime(2025, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is True
    assert result["reason"] == "Action is within scope"


def test_b_target_not_in_targets_list():
    action = {
        "engagement_id": "eng-001",
        "target": "10.0.0.1",
        "attack_class": "recon",
        "timestamp": datetime(2025, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is False
    assert "not in the engagement scope" in result["reason"]


def test_b_target_matches_excluded():
    action = {
        "engagement_id": "eng-001",
        "target": "203.0.113.50",
        "attack_class": "recon",
        "timestamp": datetime(2025, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is False
    assert "excluded" in result["reason"].lower()


def test_c_outside_time_window():
    action = {
        "engagement_id": "eng-001",
        "target": "203.0.113.10",
        "attack_class": "recon",
        "timestamp": datetime(2024, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is False
    assert "outside" in result["reason"].lower() or "authorized" in result["reason"].lower()


def test_d_attack_class_not_allowed():
    action = {
        "engagement_id": "eng-001",
        "target": "203.0.113.10",
        "attack_class": "exploitation",
        "timestamp": datetime(2025, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is False
    assert "not in the allowed classes" in result["reason"]


def test_e_target_in_cidr_but_excluded():
    action = {
        "engagement_id": "eng-001",
        "target": "203.0.113.50",
        "attack_class": "recon",
        "timestamp": datetime(2025, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is False
    assert "excluded" in result["reason"].lower()


def test_domain_target_in_scope():
    action = {
        "engagement_id": "eng-001",
        "target": "sub.example.com",
        "attack_class": "web",
        "timestamp": datetime(2025, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is True


def test_excluded_domain():
    action = {
        "engagement_id": "eng-001",
        "target": "admin.example.com",
        "attack_class": "web",
        "timestamp": datetime(2025, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is False
    assert "excluded" in result["reason"].lower()


def test_single_ip_target():
    action = {
        "engagement_id": "eng-001",
        "target": "192.168.1.100",
        "attack_class": "network",
        "timestamp": datetime(2025, 6, 15, 12, 0, 0),
    }
    result = validate(action, SCOPE)
    assert result["allowed"] is True


# --- Target matching unit tests ---

def test_exact_ip_match():
    assert _matches("192.168.1.1", "192.168.1.1") is True


def test_cidr_match():
    assert _matches("10.0.0.0/24", "10.0.0.50") is True
    assert _matches("10.0.0.0/24", "10.0.1.1") is False


def test_domain_exact_match():
    assert _matches("example.com", "example.com") is True


def test_domain_subdomain_match():
    assert _matches("example.com", "sub.example.com") is True


def test_domain_no_match():
    assert _matches("example.com", "other.com") is False


# --- Input validation unit tests ---

def test_valid_cidr():
    assert is_valid_target("10.0.0.0/16") is True


def test_valid_ip():
    assert is_valid_target("192.168.1.1") is True


def test_valid_domain():
    assert is_valid_target("example.com") is True


def test_valid_wildcard_domain():
    assert is_valid_target("*.example.com") is True


def test_invalid_target():
    assert is_valid_target("not a target") is False


def test_allowed_attack_classes_set():
    assert "recon" in ALLOWED_ATTACK_CLASSES
    assert "web" in ALLOWED_ATTACK_CLASSES
    assert "network" in ALLOWED_ATTACK_CLASSES
    assert "exploitation" in ALLOWED_ATTACK_CLASSES
    assert "social_eng" in ALLOWED_ATTACK_CLASSES
    assert "mitm" in ALLOWED_ATTACK_CLASSES
    assert len(ALLOWED_ATTACK_CLASSES) == 6


def test_endpoint_before_start():
    from scope_engine.models import ScopeFile, AuthorizationContact
    import pytest

    with pytest.raises(ValueError):
        ScopeFile(
            engagement_id="test",
            engagement_name="Bad",
            targets=["10.0.0.1"],
            start_time=datetime(2025, 6, 15, 12, 0, 0),
            end_time=datetime(2025, 6, 15, 10, 0, 0),
            allowed_attack_classes=["recon"],
            authorization_contact=AuthorizationContact(
                name="x", email="x@x.com", role="x"
            ),
            emergency_contact="x",
        )


def test_no_attack_classes():
    from scope_engine.models import ScopeFile, AuthorizationContact
    import pytest

    with pytest.raises(ValueError):
        ScopeFile(
            engagement_id="test",
            engagement_name="Bad",
            targets=["10.0.0.1"],
            start_time=datetime(2025, 6, 15, 10, 0, 0),
            end_time=datetime(2025, 6, 15, 12, 0, 0),
            allowed_attack_classes=[],
            authorization_contact=AuthorizationContact(
                name="x", email="x@x.com", role="x"
            ),
            emergency_contact="x",
        )
