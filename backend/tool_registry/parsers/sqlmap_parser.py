import re

from .enrich import enrich

# Parser verified against realistic sqlmap output (format documented at
# https://github.com/sqlmapproject/sqlmap/wiki/Usage).
#
# Sqlmap's injection point output has this multi-line structure:
#   Parameter: <name> (<method>)
#       Type: <technique_type>
#       Title: <human-readable title>
#       Payload: <injected_payload>
#
# A single parameter can have multiple technique types (e.g. boolean-based
# blind + error-based). The block is delimited by --- lines.

PARAM_RE = re.compile(r"^Parameter:\s+(\S+)\s+\(([^)]+)\)")
TYPE_RE = re.compile(r"^\s+Type:\s+(.+)$")
TITLE_RE = re.compile(r"^\s+Title:\s+(.+)$")
PAYLOAD_RE = re.compile(r"^\s+Payload:\s+(.+)$")


def parse(raw: str) -> dict:
    findings = []
    lines = raw.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        pm = PARAM_RE.match(line)
        if pm:
            param_name = pm.group(1)
            param_method = pm.group(2)
            types = []

            i += 1
            while i < len(lines):
                tl = lines[i]
                tm = TYPE_RE.match(tl)
                if tm:
                    tech = {"type": tm.group(1), "title": None, "payload": None}
                    i += 1
                    if i < len(lines) and TITLE_RE.match(lines[i]):
                        tech["title"] = TITLE_RE.match(lines[i]).group(1)
                        i += 1
                    if i < len(lines) and PAYLOAD_RE.match(lines[i]):
                        tech["payload"] = PAYLOAD_RE.match(lines[i]).group(1)
                        i += 1
                    types.append(tech)
                elif lines[i].strip() == "" or lines[i].startswith("---"):
                    i += 1
                else:
                    break

            if types:
                finding = enrich("sqlmap", {
                    "type": "sql_injection",
                    "detail": {
                        "parameter": param_name.strip(),
                        "method": param_method.strip(),
                        "techniques": types,
                    },
                })
                findings.append(finding)
        else:
            i += 1

    return {"tool": "sqlmap", "findings": findings}
