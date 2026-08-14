import yaml
from pathlib import Path
from tool_registry.registry import get_capabilities

TOOLS_YAML = Path(__file__).parent.parent / "tool_registry" / "tools.yaml"

PARAM_DESCRIPTIONS = {
    "ip_or_domain": "Target IP address or domain name",
    "domain": "Domain name",
    "url": "Full URL including protocol (e.g. http://target.com)",
    "port": "Single port number (1-65535)",
    "port_range": "Port range (e.g. '1-1000') or comma-separated list (e.g. '80,443')",
    "file_path": "Path to a file on the container filesystem",
    "gobuster_mode": "Gobuster scan mode: dir, dns, vhost, fuzz, or s3",
    "hydra_service": "Service name for hydra (e.g. ssh, ftp, http-post-form)",
    "nikto_maxtime": "Max scan duration (e.g. '10m', '120s', '1h')",
}

RISK_TIER_HINTS = {
    "passive": " (passive - auto-executes immediately, no approval needed)",
    "active_scan": " (active_scan - requires human approval before execution)",
    "exploit": " (exploit - requires human approval before execution)",
}


def generate_tool_schemas() -> list[dict]:
    with open(TOOLS_YAML) as f:
        tools = yaml.safe_load(f)

    schemas = []
    for tool in tools:
        properties = {}
        required = []

        for param_name, param_type in tool["allowed_params"].items():
            desc = PARAM_DESCRIPTIONS.get(param_type, f"Value of type {param_type}")
            if param_name in tool.get("defaults", {}):
                desc += f" (default: {tool['defaults'][param_name]})"
            if param_name == "template":
                desc += " — use the default path, do NOT guess a filename"
            properties[param_name] = {
                "type": "string",
                "description": desc,
            }
            if param_name in tool.get("required_params", [param_name]):
                required.append(param_name)

        tier_hint = RISK_TIER_HINTS.get(tool.get("risk_tier", ""), "")
        attack_class = tool.get("attack_class", "")

        schemas.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": f"{tool['description']}{tier_hint} [attack_class: {attack_class}]",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        })

    schemas.append({
        "type": "function",
        "function": {
            "name": "finish_engagement",
            "description": "Call when you have completed all necessary actions and want to provide a final summary of findings and actions taken",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Summary of all findings, actions taken, and conclusions from the engagement",
                    },
                },
                "required": ["summary"],
            },
        },
    })

    return schemas


def generate_capability_schemas() -> list[dict]:
    """The sole execution interface exposed to the reasoning model.

    Concrete binaries deliberately stay behind the capability resolver.
    """
    return [{
        "type": "function",
        "function": {
            "name": "request_capability",
            "description": "Request one investigation capability with its target parameters.",
            "parameters": {
                "type": "object",
                "properties": {
                    "capability": {"type": "string", "enum": get_capabilities()},
                    "arguments": {"type": "object"},
                },
                "required": ["capability", "arguments"],
            },
        },
    }]


def tool_summary() -> list[dict]:
    """Human-readable catalog of the registered tools, built dynamically from
    tools.yaml. Used to give the model accurate facts about what it can do."""
    with open(TOOLS_YAML) as f:
        tools = yaml.safe_load(f)
    return [
        {
            "name": t["name"],
            "risk_tier": t.get("risk_tier"),
            "attack_class": t.get("attack_class"),
            "description": t.get("description"),
            "requires_approval": t.get("risk_tier") in ("active_scan", "exploit"),
        }
        for t in tools
    ]


def get_system_prompt(state: dict, interaction_intent: str = "execution") -> str:
    from .investigate.prompts import get_system_prompt as _impl
    return _impl(state, interaction_intent=interaction_intent)
