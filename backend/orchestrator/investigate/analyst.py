"""Evidence Analyzer.

Reads completed tool executions off the session and folds their (already
enriched) findings into the investigation blackboard. This is the "parser
writes to the blackboard" step of the investigation loop, and the only place
where raw findings become knowledge: facts, hypotheses, unknowns, assets and
potential vulnerabilities are created or updated here.

The analyzer is idempotent: it tracks which sandbox jobs it has already
absorbed (board["_processed_jobs"]) so re-running it on a session never
double-counts evidence.
"""

import ipaddress
from urllib.parse import urlparse

from . import blackboard


def _extract_host(value) -> str:
    if not value:
        return ""
    s = str(value)
    if "://" in s:
        parsed = urlparse(s)
        if parsed.hostname:
            return parsed.hostname
    return s


def absorb(session: dict) -> dict:
    """Merge new job results into the blackboard. Returns the blackboard."""
    board = blackboard.ensure_blackboard(session)
    findings_so_far = session.get("findings_so_far", [])
    processed = set(board.get("_processed_jobs", []))

    # Re-sync pending approvals from the action history.
    board["pending_approvals"] = [
        a.get("approval_id")
        for a in session.get("action_history", [])
        if a.get("type") == "action" and a.get("outcome") == "pending_approval" and a.get("approval_id")
    ]

    for entry in session.get("action_history", []):
        if entry.get("type") != "action":
            continue
        outcome = entry.get("outcome", "")
        target = entry.get("target") or entry.get("params", {}).get("target", "")
        tool = entry.get("tool_name", "unknown")

        # Track pending approvals in the board marker list.
        if outcome == "pending_approval" and entry.get("approval_id"):
            blackboard.add_pending_approval(board, entry["approval_id"])

        if outcome in ("completed", "error", "timeout"):
            job_id = entry.get("job_id")
            if not job_id:
                continue
            action_str = f"{tool}@{target or '?'}"
            if outcome == "completed":
                blackboard.mark_completed_action(board, action_str)
            else:
                blackboard.mark_failed_action(board, action_str)

            if job_id in processed:
                continue

            job_findings = [f for f in findings_so_far if f.get("_job_id") == job_id]
            for finding in job_findings:
                _absorb_finding(board, finding, target=target)
            processed.add(job_id)

            # Capability bookkeeping: the completed job exercised the capability
            # that its implementation advertises; no useful findings in a
            # completed job marks that avenue as a dead end.
            capability = entry.get("capability")
            if capability:
                blackboard.mark_capability_used(board, capability)
                if not job_findings:
                    blackboard.add_dead_end(board, capability, "completed with no findings")

    board["_processed_jobs"] = sorted(processed)
    blackboard.touch(board)
    return board


def _absorb_finding(board: dict, finding: dict, target: str) -> None:
    ftype = finding.get("type")
    detail = finding.get("detail", {}) or {}
    source = finding.get("_tool", "unknown")

    # Flag genuinely interesting results for the final picture: vulnerabilities,
    # SQL injections, discovered credentials, interesting services/paths.
    interestingness = detail.get("interestingness", 0.0)
    high_value_types = {"vulnerability", "sql_injection", "credential_found"}
    if ftype in high_value_types or float(interestingness or 0.0) >= 0.8:
        blackboard.add_interesting_finding(board, finding)

    host = _extract_host(detail.get("host") or detail.get("url") or detail.get("matched") or target)

    if ftype == "port_open":
        port = detail.get("port")
        service = detail.get("service", "")
        protocol = detail.get("protocol", "tcp")
        version = detail.get("version")
        interesting = bool(detail.get("interestingness", 0) and detail.get("interestingness") >= 0.6)
        conf = detail.get("confidence", 0.5)

        blackboard.add_fact(
            board,
            f"port {port}/{protocol} is open — {service}"
            + (f" ({version})" if version else ""),
            source=source, target=host,
            confidence=conf,
            evidence=f"{service} on {host}:{port}",
            signature=f"port:{host}:{port}:{protocol}",
        )
        blackboard.note_service_asset(board, host, port, service, is_interesting=interesting)
        blackboard.answer_unknown(board, f"Discover open services on {_extract_host(host)}", source=source)

        is_web = service.lower() in ("http", "https", "http-alt", "ssl/http")
        if is_web:
            blackboard.add_unknown(board, f"Does {_extract_host(host)} expose a web application?",
                                   importance=0.9)
            blackboard.add_hypothesis(
                board,
                f"{_extract_host(host)} runs a web-facing service on port {port}" ,
                confidence=conf,
                support=f"{service} open on {_extract_host(host)}:{port}",
            )

    elif ftype == "port_filtered":
        blackboard.add_fact(
            board,
            f"port {detail.get('port')}/{detail.get('protocol')} is filtered",
            source=source, target=host, confidence=0.4,
            evidence=f"filtered port {detail.get('port')} on {host}",
            signature=f"filtered:{host}:{detail.get('port')}",
        )

    elif ftype == "subdomain":
        sub = detail.get("subdomain", "")
        parent = detail.get("parent")
        blackboard.ensure_asset(board, sub, asset_type="subdomain", parent=parent)
        blackboard.add_fact(
            board, f"subdomain discovered: {sub}",
            source=source, target=sub, confidence=0.9,
            evidence=f"subfinder listed {sub}",
            signature=f"subdomain:{sub}",
        )
        blackboard.answer_unknown(board, "Enumerate subdomains of the engagement domain", source=source)
        blackboard.answer_unknown(board, f"Enumerate subdomains of {parent or ''}".strip(), source=source)

    elif ftype == "discovered_path":
        path = detail.get("path", "/")
        status = int(detail.get("status", 0) or 0)
        interesting = 200 <= status < 400
        blackboard.note_path_asset(board, host, path, interesting=interesting)
        blackboard.add_fact(
            board, f"web path accessible: {path} (HTTP {status})",
            source=source, target=host, confidence=0.9,
            evidence=f"gobuster found {path} with status {status}",
            signature=f"path:{host}:{path}:{status}",
        )
        blackboard.answer_unknown(board, f"Does {host} expose a web application?", source=source)

    elif ftype == "vulnerability":
        name = detail.get("name", detail.get("template", "unknown"))
        severity = detail.get("severity", "info")
        target_url = detail.get("url") or detail.get("matched") or host
        blackboard.add_potential_vulnerability(
            board, name=name, severity=severity,
            target=_extract_host(target_url), source=source,
            confidence=detail.get("confidence"),
        )
        blackboard.add_hypothesis(
            board, f"{_extract_host(host)} is affected by {name}",
            confidence=detail.get("confidence", 0.5),
            support=f"nuclei matched template {name} at {target_url}",
        )

    elif ftype == "nikto_finding":
        message = detail.get("message", "")
        path = detail.get("path", "/")
        blackboard.add_fact(
            board, f"web server issue on {path}: {message}",
            source=source, target=host,
            confidence=detail.get("confidence", 0.4),
            evidence=message,
            signature=f"nikto:{host}:{path}:{message[:48]}",
        )

    elif ftype == "sql_injection":
        param = detail.get("parameter", "")
        method = detail.get("method", "")
        blackboard.add_potential_vulnerability(
            board, name=f"SQL injection in parameter '{param}'",
            severity="high", target=host, source=source, confidence=0.85,
        )
        blackboard.add_hypothesis(
            board, f"{host}{'/' + param if param else ''} is vulnerable to SQL injection",
            confidence=0.85,
            support=f"sqlmap confirmed injection in {method} parameter {param}",
        )

    elif ftype == "credential_found":
        cred_host = _extract_host(detail.get("host") or target)
        service = detail.get("service", "")
        blackboard.add_potential_vulnerability(
            board,
            name=f"weak/default credentials on {service or 'service'}",
            severity="high", target=cred_host, source=source, confidence=0.9,
        )
        blackboard.add_hypothesis(
            board, f"{cred_host} is reachable with a discovered credential",
            confidence=0.9,
            support=f"hydra found login {detail.get('login')} / password {detail.get('password')}",
        )
        blackboard.add_fact(
            board,
            f"credential found: {detail.get('login')} on {cred_host}"
            + (f":{detail.get('port')} ({service})" if detail.get('port') else ""),
            source=source, target=cred_host, confidence=0.9,
            evidence=f"hydra: {service} login={detail.get('login')}",
            signature=f"cred:{cred_host}:{detail.get('port')}:{service}:{detail.get('login')}",
        )
        blackboard.add_unknown(board, "What is the impact of the discovered credential?", importance=1.0)

    blackboard.touch(board)