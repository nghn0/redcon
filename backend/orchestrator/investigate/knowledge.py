"""Knowledge Manager.

Encodes the operational knowledge of an experienced tester into lightweight,
deterministic heuristics that answer two questions:

  1. From the current investigation state, what information is still missing?
  2. Which candidate actions could fill those gaps?

The Knowledge Manager does NOT hardcode a linear workflow. It looks at the
blackboard — phase, known facts, unknowns, assets, ports, services, paths and
potential vulnerabilities — and derives a *menu* of candidate actions, each
annotated with the objective it serves, an estimate of its information gain,
cost, risk and likelihood of usefulness. The Action Selector turns that menu
into a ranked shortlist and the LLM makes the final call.
"""

from . import blackboard
from .blackboard import (
    PHASE_RECON,
    PHASE_SERVICE_ENUM,
    PHASE_WEB_RECON,
    PHASE_EXPLOITATION,
)

# Which objective a candidate serves (used for rationale + scoring).
OBJECTIVE_ENUMERATE_PORTS = "enumerate open services and ports"
OBJECTIVE_FINGERPRINT_WEB = "identify the web technology and map the application"
OBJECTIVE_SCAN_WEB_VULNS = "check the web application for known vulnerabilities"
OBJECTIVE_ENUMERATE_SUBDOMAINS = "enumerate subdomains of the target domain"

# Capability estimates are investigator-level properties and live in the
# capability catalog (capabilities.yaml) so adding a capability never needs
# planner code. Fallbacks below only guard against an unknown capability id.
from tool_registry import capability_catalog as catalog

# Risk model aligned with the approval gate tiers in tools.yaml.
TOOL_RISK = {
    "passive": 0.05,
    "active_scan": 0.5,
    "exploit": 0.9,
}


def _cap_cost(capability: str) -> float:
    return round(float(catalog.default_cost(capability)), 2)


def _cap_risk(capability: str) -> float:
    return TOOL_RISK.get(catalog.default_risk_tier(capability), 0.5)


def _cap_gain(capability: str) -> float:
    return round(float(catalog.default_gain(capability)), 2)


# Keywords in the user goal that signal intent to test credentials / SQLi.
BRUTE_FORCE_HINTS = ("brute", "password", "credential", "login", "weak", "auth")
SQLI_HINTS = ("sql", "sqli", "injection", "database")


def _domain_of(host: str) -> str:
    host = host.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.count(".") >= 2:
        return host.split(".", 1)[1]
    return host


def _params_target(target: str) -> str:
    return target.strip()


def _has_web_service(asset: dict) -> bool:
    for s in asset.get("services", []):
        if s.lower() in ("http", "https", "http-alt", "ssl/http"):
            return True
    return False


def _asset_ran_action(board: dict, asset: str, capability: str) -> bool:
    asset = asset.strip().lower()
    for action in board.get("completed_actions", []):
        if action.lower().startswith(capability + "@") and asset in action.lower():
            return True
    return False


def web_url_of(asset: dict) -> str | None:
    """Choose a URL form of the asset for web tools."""
    target = asset.get("target", "")
    for s in asset.get("services", []):
        if s.lower() in ("http",):
            return f"http://{target}"
        if s.lower() in ("https", "ssl/http"):
            return f"https://{target}"
    # No explicit protocol hint: default assumptions.
    ports = asset.get("ports", [])
    if 443 in ports:
        return f"https://{target}"
    if 8080 in ports or 8443 in ports:
        return f"{'https' if 8443 in ports else 'http'}://{target}:{8443 if 8443 in ports else 8080}"
    return f"http://{target}"


def generate_candidates(board: dict, scope_targets: list[str], goal: str = "") -> list[dict]:
    """Build the candidate action menu for the current investigation state.

    Each candidate: {capability, target, params, objective, info_gain, cost,
    risk, likelihood, phase, note}. Hosts are only suggested when they fall
    inside the engagement scope; real safety is still enforced by the Scope
    Engine at execution time.
    """
    candidates: list[dict] = []
    scope_hosts = [str(t).strip() for t in scope_targets if str(t).strip()]
    if not scope_hosts:
        return candidates

    primary = scope_hosts[0]
    goal_l = goal.lower()
    assets = board.get("assets", [])
    done = set(board.get("completed_actions", [])) | set(board.get("failed_actions", []))

    def add(capability, target, params, objective, info_gain, likelihood,
            phase, note="", rationale=""):
        action_str = f"{capability}@{target}"
        if action_str in done:
            return
        candidates.append({
            "capability": capability,
            "target": target,
            "params": params,
            "objective": objective,
            "info_gain": round(info_gain, 2),
            "cost": _cap_cost(capability),
            "risk": _cap_risk(capability),
            "likelihood": round(likelihood, 2),
            "phase": phase,
            "note": note,
            "rationale": rationale or f"to {objective}",
        })

    # --- Phase: recon ------------------------------------------------------
    # If no asset has been probed yet, the single highest-value question is
    # "what is actually exposed?".
    probed = [a for a in assets if a.get("ports")]
    for host in scope_hosts:
        port_asset = next((a for a in assets if str(a.get("target", "")).strip().lower() == host.lower()), None)
        if not port_asset or not port_asset.get("ports"):
            add(
                "network_discovery", host,
                {"target": host, "ports": "1-1000"},
                OBJECTIVE_ENUMERATE_PORTS,
                info_gain=0.9 if not assets else 0.5,
                likelihood=0.95,
                phase=PHASE_RECON,
                note="no service enumeration on this target yet",
            )

    # Subdomain enumeration for domain-scope targets.
    domains = [h for h in scope_hosts if "." in h and not h.replace(".", "").isdigit()]
    for domain in domains:
        got_sub = any(
            a.get("type") == "subdomain"
            for a in board.get("assets", [])
        )
        if not _asset_ran_action(board, domain, "subdomain_enumeration"):
            add(
                "subdomain_enumeration", domain,
                {"target": domain},
                OBJECTIVE_ENUMERATE_SUBDOMAINS,
                info_gain=0.7 if not got_sub else 0.3,
                likelihood=0.8,
                phase=PHASE_RECON,
                note="passive, zero footprint",
            )

    # --- Phase: service/web -------------------------------------------------
    for asset in assets:
        host = asset.get("target", "")
        if not host:
            continue
        # Only suggest web actions against hosts that are in scope.
        if not _host_in_scope(host, scope_hosts):
            continue
        if not _has_web_service(asset):
            continue

        url = web_url_of(asset)
        if not _asset_ran_action(board, host, "technology_detection"):
            add(
                "technology_detection", host,
                {"target": host},
                "scan the web app for technology and known vulnerabilities",
                info_gain=0.8, likelihood=0.85,
                phase=PHASE_WEB_RECON,
                note="HTTP service detected",
            )
        if not _asset_ran_action(board, url, "directory_discovery"):
            add(
                "directory_discovery", url,
                {"target": url, "mode": "dir", "wordlist": "/usr/share/wordlists/common.txt"},
                "map directories and files on the web application",
                info_gain=0.75, likelihood=0.8,
                phase=PHASE_WEB_RECON,
                note="HTTP service detected",
            )
        if not _asset_ran_action(board, host, "web_server_audit"):
            port = 8443 if 8443 in asset.get("ports", []) else (
                8080 if 8080 in asset.get("ports", []) else
                (443 if 443 in asset.get("ports", []) else 80)
            )
            add(
                "web_server_audit", host,
                {"target": host, "port": str(port), "maxtime": "10m"},
                "check common web server misconfigurations",
                info_gain=0.5, likelihood=0.55,
                phase=PHASE_WEB_RECON,
                note="broader web server check",
            )

    # --- Skill-gated candidates (goal keywords only, high risk) -------------
    if any(k in goal_l for k in SQLI_HINTS):
        # Only request validation when a plausible web target exists.
        for asset in assets:
            if _host_in_scope(asset.get("target", ""), scope_hosts) and _has_web_service(asset):
                url = web_url_of(asset)
                if not _asset_ran_action(board, url, "sql_injection_validation"):
                    add(
                        "sql_injection_validation", url,
                        {"target": url},
                        "confirm SQL injection on the web application",
                        info_gain=0.8, likelihood=0.5,
                        phase=PHASE_EXPLOITATION,
                        note="explicit user goal mentions SQL testing",
                    )

    if any(k in goal_l for k in BRUTE_FORCE_HINTS):
        for asset in assets:
            host = asset.get("target", "")
            if not _host_in_scope(host, scope_hosts) or not asset.get("ports"):
                continue
            # ports and services are tracked in independent lists on the asset,
            # so resolve the service by port index instead of zipping (which can
            # misalign when a port was recorded without a service and vice versa).
            service_by_port: dict = {}
            for p, s in zip(asset.get("ports", []), asset.get("services", [])):
                service_by_port.setdefault(p, s)
            for port in asset.get("ports", []):
                service = str(service_by_port.get(port, "")).lower()
                if service not in ("ssh", "ftp", "telnet", "rdp", "mysql"):
                    continue
                if _asset_ran_action(board, host, "credential_attack"):
                    break
                add(
                    "credential_attack", host,
                    {"target": host, "service": service},
                    f"test for weak credentials on {service}",
                    info_gain=0.6, likelihood=0.35,
                    phase=PHASE_EXPLOITATION,
                    note="explicit user goal mentions credential testing",
                )
                break

    # Self-healing: if there are open questions but NO candidate can resolve
    # them, we have nothing more to learn with the available tools — signal it.
    return candidates


def _host_in_scope(host: str, scope_hosts: list[str]) -> bool:
    if not host:
        return False
    host = host.strip().lower()
    for s in scope_hosts:
        s = s.strip().lower()
        if s == host:
            return True
        try:
            if host.endswith(s.lstrip("*.")) and "." in host:
                return True
        except Exception:
            pass
    return False


def summarize_gaps(board: dict, goal: str = "") -> str:
    """A short natural-language statement of what is still missing, used in the
    compact LLM context to focus the reasoning loop."""
    open_unknowns = blackboard.open_unknowns(board)
    if not open_unknowns:
        return "No open questions remain — the picture is complete."
    top = sorted(open_unknowns, key=lambda u: -u.get("importance", 0))[:3]
    return "; ".join(u["question"] for u in top)
