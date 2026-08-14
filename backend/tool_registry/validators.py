import re
import ipaddress

IP_OR_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "local"}


def validate_ip_or_domain(value: str) -> bool:
    value = value.strip()
    if value.lower() in LOCALHOST_NAMES:
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    if IP_OR_DOMAIN_RE.match(value):
        return True
    return False


DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_domain(value: str) -> bool:
    value = value.strip()
    if value.lower() in LOCALHOST_NAMES:
        return True
    if DOMAIN_RE.match(value):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return False


URL_HOST_RE = re.compile(
    r"^https?://"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    r"(?::\d{1,5})?"
    r"(?:/.*)?$"
)

URL_IP_RE = re.compile(
    r"^https?://"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::\d{1,5})?"
    r"(?:/.*)?$"
)

URL_IPV6_RE = re.compile(
    r"^https?://"
    r"\[([a-fA-F0-9:.]+)\]"
    r"(?::\d{1,5})?"
    r"(?:/.*)?$"
)


def validate_url(value: str) -> bool:
    value = value.strip()
    if URL_HOST_RE.match(value):
        return True
    m = URL_IP_RE.match(value)
    if m:
        try:
            ipaddress.ip_address(m.group(1))
            return True
        except ValueError:
            pass
    m = URL_IPV6_RE.match(value)
    if m:
        try:
            ipaddress.ip_address(m.group(1))
            return True
        except ValueError:
            pass
    if value.lower() in LOCALHOST_NAMES:
        return True
    return False


PORT_RE = re.compile(r"^\d{1,5}$")


def validate_port(value: str) -> bool:
    value = value.strip()
    if not PORT_RE.match(value):
        return False
    port = int(value)
    return 1 <= port <= 65535


PORT_RANGE_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")


def validate_port_range(value: str) -> bool:
    value = value.strip()
    if not PORT_RANGE_RE.match(value):
        return False
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            if not (lo.isdigit() and hi.isdigit()):
                return False
            if not (1 <= int(lo) <= int(hi) <= 65535):
                return False
        else:
            if not part.isdigit():
                return False
            if not (1 <= int(part) <= 65535):
                return False
    return True


FILE_PATH_RE = re.compile(r"^[\w\-./\\~]+$")


def validate_file_path(value: str) -> bool:
    value = value.strip()
    if not FILE_PATH_RE.match(value):
        return False
    if ".." in value:
        return False
    return True


GOBUSTER_MODE_RE = re.compile(r"^(dir|dns|vhost|fuzz|s3)$")


def validate_gobuster_mode(value: str) -> bool:
    value = value.strip().lower()
    return bool(GOBUSTER_MODE_RE.match(value))


HYDRA_SERVICE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9\-_]*$")


def validate_hydra_service(value: str) -> bool:
    value = value.strip()
    return bool(HYDRA_SERVICE_RE.match(value))


NIKTO_MAXTIME_RE = re.compile(r"^\d+[smh]$")


def validate_nikto_maxtime(value: str) -> bool:
    value = value.strip()
    return bool(NIKTO_MAXTIME_RE.match(value))


VALIDATORS = {
    "ip_or_domain": validate_ip_or_domain,
    "domain": validate_domain,
    "url": validate_url,
    "port": validate_port,
    "port_range": validate_port_range,
    "file_path": validate_file_path,
    "gobuster_mode": validate_gobuster_mode,
    "hydra_service": validate_hydra_service,
    "nikto_maxtime": validate_nikto_maxtime,
}
