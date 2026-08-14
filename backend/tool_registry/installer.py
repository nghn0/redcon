"""Installer integration for the capability layer.

The resolver answers "which tool fulfils this capability?"; the installer
answers "make that tool available".  A required capability that is only
*installable* is brought up automatically — install, verify, then the registry
reports it as healthy for the rest of the engagement.

Safety: installation is a host-affecting action and is gated the same way as a
scan — it flows through the Approval Gate.  The orchestrator creates an
approval record; a human approves in the Approvals UI; only then does this
module run the registered install command and re-verify.

To installers, a "tool" is always data from tools.yaml.  No installer ever
points at a planner-provided binary path.
"""

from __future__ import annotations

from .registry import (
    get_tool,
    install_tool,
    is_tool_healthy,
    verify_tool,
)


def ensure_tool(tool_name: str) -> dict:
    """Install ``tool_name`` if needed and verify it. Idempotent.

    Returns ``{"status": "installed"|"installable"|"unavailable", ...}`` where
    ``installable`` means install failed or the tool is already present but
    failed verification.
    """
    if is_tool_healthy(tool_name):
        return {"status": "installed", "tool_name": tool_name, "installed": True, "verified": True, "output": f"Tool '{tool_name}' is healthy"}

    result = install_tool(tool_name)
    verified = verify_tool(tool_name)
    healthy = is_tool_healthy(tool_name)

    return {
        "status": "installed" if healthy else "installable",
        "tool_name": tool_name,
        "installed": result.get("installed", False),
        "verified": verified,
        "output": result.get("output", ""),
    }


def install_for_capability(capability: str, resolver) -> dict:
    """Best-effort bring-up of the best installable implementation of a
    capability. ``resolver`` is the capability resolver module/service so the
    installer stays registry-driven (no planner tool knowledge here)."""
    resolution = resolver.resolve(capability)
    if resolution.status == "installed":
        return {"status": "installed", "tool_name": resolution.tool_name} | {"resolution": resolution}
    if resolution.installable is None:
        return {"status": "unavailable", "tool_name": None, "resolution": resolution}
    tool_name = resolution.installable.tool_name
    result = ensure_tool(tool_name)
    result["capability"] = capability
    result["resolution"] = resolution
    return result


def verify_tool_health(tool_name: str) -> dict:
    """Surfaced for the Tool Registry / status endpoints. Returns metadata only;
    never executes anything on the host."""
    tool = get_tool(tool_name)
    return {
        "tool_name": tool_name,
        "installed": is_tool_healthy(tool_name),
        "verification_command": tool.get("verification_command", ""),
        "install_command": tool.get("install_command", ""),
    }