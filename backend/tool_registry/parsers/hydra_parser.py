import re

from .enrich import enrich

HYDRA_LOGIN_RE = re.compile(
    r"^\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)$",
    re.MULTILINE,
)


def parse(raw: str) -> dict:
    findings = []
    for match in HYDRA_LOGIN_RE.finditer(raw):
        finding = enrich("hydra", {
            "type": "credential_found",
            "detail": {
                "port": int(match.group(1)),
                "service": match.group(2),
                "host": match.group(3),
                "login": match.group(4),
                "password": match.group(5),
            },
        })
        findings.append(finding)
    return {"tool": "hydra", "findings": findings}
