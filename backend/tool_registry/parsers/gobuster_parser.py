import re

from .enrich import enrich

# Verified against real gobuster v3.8.2 output against http://demo.testfire.net.
# Real format (dir mode):
#   <path>    (Status: <code>) [Size: <size>]
#   <path>    (Status: <code>) [Size: <size>] [--> <redirect_target>]
# Paths may have leading whitespace (fixed-width columns), variable spacing.
# Redirect section is optional (only present on 3xx responses).

GOBUSTER_LINE_RE = re.compile(
    r"^\s*(\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\](?:\s+\[-->\s+(\S+)\])?\s*$"
)


def parse(raw: str) -> dict:
    findings = []
    for line in raw.strip().splitlines():
        m = GOBUSTER_LINE_RE.match(line)
        if m:
            finding = {
                "type": "discovered_path",
                "detail": {
                    "path": m.group(1),
                    "status": int(m.group(2)),
                    "size": int(m.group(3)),
                },
            }
            redirect = m.group(4)
            if redirect:
                finding["detail"]["redirect_to"] = redirect
            findings.append(enrich("gobuster", finding))
    return {"tool": "gobuster", "findings": findings}
