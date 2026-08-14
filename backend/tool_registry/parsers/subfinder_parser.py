# Verified against real subfinder output (0 subdomains for localhost — empty output handled).
# subfinder -silent outputs one subdomain per line.
# Source: https://github.com/projectdiscovery/subfinder (README examples)

from .enrich import enrich


def parse(raw: str) -> dict:
    findings = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if line:
            finding = enrich("subfinder", {
                "type": "subdomain",
                "detail": {"subdomain": line},
            })
            findings.append(finding)
    return {"tool": "subfinder", "findings": findings}
