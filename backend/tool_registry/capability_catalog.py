"""Capability catalog: the authoritative vocabulary of the investigation engine.

Defines every capability identifier the reasoning loop may request, together
with the metadata the resolver, scorer and prompt need to reason about a
capability without ever naming a tool. Data-driven from ``capabilities.yaml``;
adding a capability is a YAML change, not a code change.
"""

from __future__ import annotations

from pathlib import Path

import yaml

CATALOG_YAML = Path(__file__).parent / "capabilities.yaml"


def _load() -> dict:
    with open(CATALOG_YAML) as f:
        return yaml.safe_load(f) or {}


def catalog() -> dict[str, dict]:
    """All registered capabilities -> {category, description, cost, risk, gain, phase}."""
    return _load()


def capability_names() -> list[str]:
    return sorted(catalog().keys())


def get_capability(capability: str) -> dict:
    return catalog().get(capability, {})


def default_cost(capability: str) -> float:
    return float(get_capability(capability).get("default_cost", 0.3))


def default_risk_tier(capability: str) -> str:
    return str(get_capability(capability).get("default_risk", "active_scan"))


def default_gain(capability: str) -> float:
    return float(get_capability(capability).get("default_gain", 0.5))


def default_phase(capability: str) -> str:
    return str(get_capability(capability).get("phase", ""))


def describe(capability: str) -> str:
    """Natural-language description for prompts/schemas; falls back safely."""
    meta = get_capability(capability)
    return meta.get("description", f"Performs {capability.replace('_', ' ')}")