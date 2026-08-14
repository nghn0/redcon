import json
import re

from .enrich import enrich

# nuclei can emit either JSON lines (with -jsonl, nuclei v3) or human-readable
# lines like:
#   [waf-detect:apachegeneric] [http] [info] http://scanme.nmap.org
# The -jsonl flag is set in tools.yaml, but the parser also falls back to the
# readable format so findings are never silently dropped.

_HUMAN_RE = re.compile(
    r"\[(?P<name>[^:\]]+)(?::(?P<extra>[^\]]+))?\]"
    r" \[(?P<proto>\w+)\] \[(?P<severity>\w+)\] (?P<url>\S+)"
)


def parse(raw: str) -> dict:
    findings = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            finding = enrich("nuclei", {
                "type": "vulnerability",
                "detail": {
                    "template": obj.get("template-id", ""),
                    "name": obj.get("info", {}).get("name", ""),
                    "severity": obj.get("info", {}).get("severity", ""),
                    "matched": obj.get("matched-at", ""),
                    "url": obj.get("host", ""),
                },
            })
            findings.append(finding)
            continue
        except json.JSONDecodeError:
            pass

        m = _HUMAN_RE.match(line)
        if m:
            finding = enrich("nuclei", {
                "type": "vulnerability",
                "detail": {
                    "template": m.group("extra") or m.group("name"),
                    "name": m.group("name"),
                    "severity": m.group("severity"),
                    "matched": m.group("url"),
                    "url": m.group("url"),
                },
            })
            findings.append(finding)
    return {"tool": "nuclei", "findings": findings}
