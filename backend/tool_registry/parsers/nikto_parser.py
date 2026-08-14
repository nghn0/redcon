import re

from .enrich import enrich

# Parser written from documented output format.
# nikto outputs lines like:
#   + /path: Some description (See https://...)
#   + Server: Apache/2.4.41
# Source: https://github.com/sullo/nikto/wiki

NIKTO_LINE_RE = re.compile(
    r"^\+ (?:\/)?(.+?):\s+(.+)$"
)


def parse(raw: str) -> dict:
    findings = []
    for line in raw.strip().splitlines():
        line = line.strip()
        m = NIKTO_LINE_RE.match(line)
        if m:
            finding = enrich("nikto", {
                "type": "nikto_finding",
                "detail": {
                    "path": m.group(1).strip() or "/",
                    "message": m.group(2).strip(),
                },
            })
            findings.append(finding)
    return {"tool": "nikto", "findings": findings}
