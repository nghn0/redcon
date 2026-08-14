import re

from .enrich import enrich

PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|filtered|closed|unfiltered)\s+(\S+)[ \t]*(.*)$",
    re.MULTILINE,
)


def parse(raw: str) -> dict:
    findings = []
    for match in PORT_RE.finditer(raw):
        port = int(match.group(1))
        protocol = match.group(2)
        state = match.group(3)
        service = match.group(4)
        version_raw = match.group(5).strip() if match.lastindex >= 5 else ""
        version = version_raw if version_raw and version_raw != "?" else None
        finding = enrich("nmap", {
            "type": f"port_{state}",
            "detail": {
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
            },
        })
        findings.append(finding)
    return {"tool": "nmap", "findings": findings}
