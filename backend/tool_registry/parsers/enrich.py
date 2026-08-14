"""Shared intelligence enrichment for parser findings.

Every parser in this package calls `enrich(tool_name, finding)` before
returning so that findings carry structured intelligence the investigation
blackboard can consume directly:

  - service / technology / version
  - confidence  (0-1) that the observation is real
  - interestingness (0-1) of the finding for the assessment
  - relationships (links to other assets, e.g. parent domain)
  - follow_ups (suggested next actions, consumed by the Knowledge Manager)

Enrichment is additive: it only APPENDS keys inside `finding["detail"]` and
never alters the existing keys the parsers/tests already rely on.
"""

import re

# Service names that signal an interesting, attack-relevant surface.
# Shared with the orchestrator investigation loop (see blackboard.py).
INTERESTING_SERVICES = {
    "http", "https", "http-alt", "ssl/http", "ssh", "rdp", "ms-wbt-server",
    "smb", "microsoft-ds", "netbios-ssn", "mysql", "mssql", "ms-sql-s",
    "postgresql", "mongodb", "redis", "couchdb", "ftp", "telnet", "smtp",
    "pop3", "imap", "vnc", "docker", "oracle", "db2", "ldap", "kerberos",
    "snmp", "webmin", "mysql-via-ssl", "rpcbind",
}

VERSION_TECHNOLOGY = [
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"apache", re.I), "Apache"),
    (re.compile(r"microsoft-iis|^iis/", re.I), "IIS"),
    (re.compile(r"tomcat", re.I), "Apache Tomcat"),
    (re.compile(r"jetty", re.I), "Jetty"),
    (re.compile(r"openssh", re.I), "OpenSSH"),
    (re.compile(r"node\.?js", re.I), "Node.js"),
    (re.compile(r"express", re.I), "Express"),
    (re.compile(r"openbsd", re.I), "OpenBSD"),
    (re.compile(r"proftpd", re.I), "ProFTPD"),
    (re.compile(r"exim|postfix|sendmail", re.I), "Mail server"),
    (re.compile(r"nginx/", re.I), "nginx"),
]


def _infer_technology(version: str | None) -> str | None:
    if not version:
        return None
    for rx, name in VERSION_TECHNOLOGY:
        if rx.search(version):
            return name
    # Common service -> product when no version hint.
    return None


def _web_follow_up(host: str, port=None) -> list[dict]:
    port_suffix = f":{port}" if port else ""
    return [
        {
            "tool": "nuclei",
            "objective": "fingerprint the web technology and known CVEs",
            "params": {"target": f"{host}{port_suffix}"},
        },
        {
            "tool": "gobuster",
            "objective": "map directories and files on the web application",
            "params": {"target": f"http://{host}{port_suffix}", "mode": "dir"},
        },
        {
            "tool": "nikto",
            "objective": "check common web server misconfigurations",
            "params": {"target": host, "port": str(port or 80)},
        },
    ]


def enrich(tool_name: str, finding: dict) -> dict:
    """Attach structured intelligence to a single finding (in place + returned)."""
    ftype = finding.get("type")
    detail = finding.setdefault("detail", {})
    host = detail.get("host") or detail.get("url") or detail.get("matched") or ""

    if ftype == "port_open":
        service = detail.get("service", "")
        port = detail.get("port")
        detail["technology"] = _infer_technology(detail.get("version"))
        detail["confidence"] = 0.7 if detail.get("version") else 0.5
        detail["interestingness"] = 1.0 if service.lower() in INTERESTING_SERVICES else 0.35
        detail["relationships"] = [{"type": "exposes_service", "value": service}]
        follow = []
        if service.lower() in ("http", "https", "http-alt", "ssl/http"):
            follow = _web_follow_up(host or detail.get("target", ""), port)
        detail["follow_ups"] = follow

    elif ftype == "port_filtered":
        detail["confidence"] = 0.4
        detail["interestingness"] = 0.2
        detail["follow_ups"] = []
        detail["relationships"] = []

    elif ftype == "subdomain":
        sub = detail.get("subdomain", "")
        parts = sub.split(".")
        detail["parent"] = ".".join(parts[1:]) if len(parts) > 1 else None
        detail["asset_type"] = "subdomain"
        detail["confidence"] = 0.9
        detail["interestingness"] = 0.7
        detail["relationships"] = (
            [{"type": "child_of", "value": detail["parent"]}] if detail["parent"] else []
        )
        detail["follow_ups"] = []

    elif ftype == "vulnerability":
        severity = detail.get("severity", "info")
        detail["technology"] = _infer_technology(detail.get("name", ""))
        detail["confidence"] = {
            "critical": 0.9, "high": 0.8, "medium": 0.65, "low": 0.5, "info": 0.35,
        }.get(severity.lower(), 0.5)
        detail["interestingness"] = {
            "critical": 1.0, "high": 0.85, "medium": 0.55, "low": 0.25, "info": 0.1,
        }.get(severity.lower(), 0.2)
        detail["relationships"] = []
        detail["follow_ups"] = []

    elif ftype == "discovered_path":
        status = int(detail.get("status", 0) or 0)
        detail["interestingness"] = 0.8 if 200 <= status < 400 else 0.25
        detail["confidence"] = 0.9
        detail["relationships"] = []
        if detail.get("redirect_to"):
            detail["relationships"].append({"type": "redirects_to", "value": detail["redirect_to"]})
        detail["follow_ups"] = [
            {
                "tool": "sqlmap",
                "objective": "probe discovered paths/parameters for SQL injection",
                "params": {"target": host},
                "when": "a discovered path has a query parameter",
            }
        ]

    elif ftype == "nikto_finding":
        detail["confidence"] = 0.4
        detail["interestingness"] = 0.5
        detail["relationships"] = []
        detail["follow_ups"] = []

    elif ftype == "sql_injection":
        detail["confidence"] = 0.85
        detail["interestingness"] = 1.0
        detail["technology"] = "SQL"
        detail["relationships"] = []
        detail["follow_ups"] = [
            {
                "tool": "sqlmap",
                "objective": "confirm and fingerprint the injection technique",
                "params": {"target": host},
            }
        ]

    elif ftype == "credential_found":
        detail["confidence"] = 0.9
        detail["interestingness"] = 1.0
        detail["relationships"] = [
            {"type": "served_by", "value": f"port {detail.get('port')} {detail.get('service')}"}
        ]
        detail["follow_ups"] = [
            {
                "tool": "hydra",
                "objective": "verify the found credential unlocks access",
                "params": {"target": detail.get("host", ""), "service": detail.get("service", "")},
            }
        ]

    elif ftype == "subdomain_unknown":
        detail["confidence"] = 0.5
        detail["interestingness"] = 0.3
        detail["relationships"] = []
        detail["follow_ups"] = []

    return finding


def enrich_all(tool_name: str, findings: list[dict]) -> list[dict]:
    enriched = []
    for f in findings:
        enriched.append(enrich(tool_name, f))
    return enriched