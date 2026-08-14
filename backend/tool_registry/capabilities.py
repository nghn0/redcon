"""Capability resolver: translate an investigator need into a registry tool.

Reasoning code deals exclusively in capability identifiers.  Tool-specific
selection, platform support, health and installation live here with the
registry.

The resolver answers two questions:

  1. "Which registered implementation is the best one already available?"
  2. "If none is, which registered implementation is the best one to install?"

Both answers respect the capability catalog, per-tool priority/confidence,
platform compatibility, host health and optional user tool preferences.  The
planner never names a tool — it names a capability, and the resolver picks the
implementation.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field

from .capability_catalog import describe
from .registry import get_all_tools, is_tool_healthy, is_tool_installed, get_tool_requirements

STATUS_INSTALLED = "installed"
STATUS_INSTALLABLE = "installable"
STATUS_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ToolCandidate:
    """One concrete implementation of a capability."""

    tool_name: str
    installed: bool
    healthy: bool
    status: str  # installed | installable | unavailable (in terms of host)
    score: float
    priority: int = 0
    confidence: float = 0.0
    risk_tier: str = "active_scan"
    attack_class: str = "recon"
    installable: bool = True
    install_command: str = ""
    verification_command: str = ""
    supported_platforms: list[str] = field(default_factory=list)
    requirements: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass(frozen=True)
class CapabilityResolution:
    capability: str
    tool_name: str | None  # selected implementation (installed if any)
    status: str  # installed | installable | unavailable
    score: float = 0.0
    reason: str = ""
    # Always filled: best already-available and, separately, best installable
    # candidate so the orchestrator can decide between execute / install.
    installed: ToolCandidate | None = None
    installable: ToolCandidate | None = None
    candidates: list[ToolCandidate] = field(default_factory=list)

    @property
    def description(self) -> str:
        return describe(self.capability)


def capabilities() -> list[str]:
    """All capabilities satisfied by at least one registered tool."""
    return sorted({c for tool in get_all_tools() for c in tool.get("capabilities", [])})


def _score_tool(capability: str, tool: dict, preferences: set[str]) -> ToolCandidate:
    installed = tool.get("execution_environment") == "sandbox" or is_tool_installed(tool["name"])
    healthy = tool.get("execution_environment") == "sandbox" or is_tool_healthy(tool["name"])
    requirements = get_tool_requirements(tool["name"])
    req_met = not requirements or is_tool_installed(tool["name"])

    # Ranking knobs are registry-controlled; this layer only weights them.
    score = float(tool.get("priority", 0)) + 100 * float(tool.get("confidence", 0))
    if tool["name"] in preferences:
        score += 1_000
    if installed and healthy:
        score += 50
    if not req_met:
        score -= 500

    status = STATUS_INSTALLED if healthy else (STATUS_INSTALLABLE if req_met else STATUS_UNAVAILABLE)
    risk_tier = tool.get("risk_tier", "active_scan")
    installable = tool.get("execution_environment") != "sandbox"

    reason_parts = ["registry priority and confidence"]
    if tool["name"] in preferences:
        reason_parts.append("user preference")
    if healthy:
        reason_parts.append("verified on host")
    elif installed and not healthy:
        reason_parts.append("present but failed verification")
    if not req_met:
        reason_parts.append(f"missing host requirements: {', '.join(requirements)}")

    return ToolCandidate(
        tool_name=tool["name"],
        installed=installed,
        healthy=healthy,
        status=status,
        score=round(score, 2),
        priority=int(tool.get("priority", 0)),
        confidence=float(tool.get("confidence", 0)),
        risk_tier=risk_tier,
        attack_class=tool.get("attack_class", "recon"),
        installable=installable,
        install_command=tool.get("install_command", ""),
        verification_command=tool.get("verification_command", ""),
        supported_platforms=[str(p) for p in tool.get("supported_platforms", [])],
        requirements=requirements,
        reason="; ".join(reason_parts),
    )


def resolve(capability: str, *, preferences: dict | None = None) -> CapabilityResolution:
    """Return the best installed implementation, else the best installable one.

    Ranking is registry-driven: priority, confidence, platform compatibility,
    health (binary present + verification), and optional user tool preference.
    Adding a tool or replacing one requires only registry data; the planner is
    unchanged.
    """
    current_platform = platform.system().lower()
    preferred = set((preferences or {}).get("preferred_tools", []))

    candidates: list[ToolCandidate] = []
    for tool in get_all_tools():
        if capability not in tool.get("capabilities", []):
            continue
        platforms = [str(p).lower() for p in tool.get("supported_platforms", [])]
        if platforms and current_platform not in platforms:
            continue
        candidate = _score_tool(capability, tool, preferred)
        # Sandbox-executed tools are always present from the platform's point
        # of view; they rank as installed regardless of the host binary.
        if tool.get("execution_environment") == "sandbox":
            candidates.append(candidate)
        else:
            candidates.append(candidate)

    candidates.sort(key=lambda c: c.score, reverse=True)

    installed = next((c for c in candidates if c.status == STATUS_INSTALLED), None)
    installable = next((c for c in candidates if c.status != STATUS_INSTALLED), None)

    if not candidates:
        return CapabilityResolution(
            capability, None, STATUS_UNAVAILABLE,
            reason="No compatible registered implementation",
            candidates=[],
        )

    selected = installed or installable
    status = STATUS_INSTALLED if installed else (STATUS_INSTALLABLE if selected else STATUS_UNAVAILABLE)
    return CapabilityResolution(
        capability,
        selected.tool_name if selected else None,
        status,
        score=selected.score if selected else 0.0,
        reason=selected.reason if selected else "",
        installed=installed,
        installable=installable,
        candidates=candidates,
    )


def resolve_all_for_capabilities(capabilities: list[str], *, preferences: dict | None = None) -> dict[str, CapabilityResolution]:
    """Resolve a whole required menu at once (used by the planner/shortlist)."""
    return {c: resolve(c, preferences=preferences) for c in capabilities}