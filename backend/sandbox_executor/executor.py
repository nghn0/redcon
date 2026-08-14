import os
import json
import threading
import time
import shutil
import shlex
import socket
import ipaddress
import hashlib
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path

import docker
from docker.errors import DockerException, NotFound, ImageNotFound
from docker import DockerClient
import requests
import docker.types

from tool_registry.registry import get_tool, build_command, ToolRegistryError
from scope_engine.validation import validate as validate_action
from scope_engine import storage
from approval_gate.gate import create_approval

RUNS_DIR = Path(__file__).parent.parent / "data" / "runs"
NETWORK_PREFIX = "redteam-net-"
GATEWAY_PREFIX = "redteam-gw-"
EGRESS_NET = "redteam-egress"
DEFAULT_TIMEOUT = 900
DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = 1.0
IMAGE_NAME = "redteam-tools:latest"

_GW_STATE_PATH = Path(__file__).parent.parent / "data" / ".gateway_state.json"
_gw_state_lock = threading.Lock()
_SUBFINDER_CONFIG = Path(__file__).parent / "provider-config.yaml"

# Async build job tracking
_build_jobs: dict[str, dict] = {}
_build_jobs_lock = threading.Lock()
_build_counter = 0
BUILD_TIMEOUT = 900  # 15 minutes max for image build

def _docker_client(timeout: int = 650) -> DockerClient:
    host = os.environ.get("DOCKER_HOST")
    if host:
        return docker.DockerClient(base_url=host, timeout=timeout)
    for sock in ["~/.docker/run/docker.sock", "/var/run/docker.sock"]:
        expanded = os.path.expanduser(sock)
        if os.path.exists(expanded):
            return docker.DockerClient(base_url=f"unix://{expanded}", timeout=timeout)
    return docker.from_env(timeout=timeout)


EXTRA_CAPS = {
    "nmap": ["NET_RAW"],
}


class ExecutorError(Exception):
    pass


def _resolve_target(target: str) -> list[str]:
    target = target.strip()
    if not target:
        return []

    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return [str(net)]
        ip = ipaddress.ip_address(target)
        return [str(ip)]
    except ValueError:
        pass

    try:
        addrs = socket.getaddrinfo(target, None)
        ips = set()
        for addr in addrs:
            try:
                ipaddress.ip_address(addr[4][0])
                ips.add(addr[4][0])
            except ValueError:
                pass
        return list(ips)
    except socket.gaierror:
        return []


def _engagement_subnet(engagement_id: str) -> str:
    h = hashlib.md5(engagement_id.encode()).hexdigest()
    idx = int(h[:4], 16) % 200 + 1
    return f"172.30.{idx}.0/24"


def _gateway_ip_from_subnet(subnet: str) -> str:
    net = ipaddress.ip_network(subnet, strict=False)
    return str(net.network_address + 2)


def _bridge_ip_from_subnet(subnet: str) -> str:
    net = ipaddress.ip_network(subnet, strict=False)
    return str(net.network_address + 1)


def _engagement_subnet_v6(engagement_id: str) -> str:
    h = hashlib.md5(engagement_id.encode()).hexdigest()
    idx = int(h[:4], 16) % 200 + 1
    return f"fd00:{idx}::/64"


def _gateway_ip_from_subnet_v6(subnet: str) -> str:
    net = ipaddress.IPv6Network(subnet, strict=False)
    return str(net.network_address + 2)


def _bridge_ip_from_subnet_v6(subnet: str) -> str:
    net = ipaddress.IPv6Network(subnet, strict=False)
    return str(net.network_address + 1)


EGRESS_SUBNET_V4 = "172.19.0.0/16"
EGRESS_GATEWAY_V4 = "172.19.0.1"
EGRESS_SUBNET_V6 = "fd00:ffff::/64"
EGRESS_GATEWAY_V6 = "fd00:ffff::1"


def _ip_table_for(ip_str: str) -> str | None:
    """Return 'iptables' or 'ip6tables' based on whether ip_str is IPv4 or IPv6.
    Accepts both single IPs and CIDR notation. Returns None if unparseable."""
    try:
        obj = ipaddress.ip_address(ip_str)
        return "ip6tables" if isinstance(obj, ipaddress.IPv6Address) else "iptables"
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
        return "ip6tables" if isinstance(net, ipaddress.IPv6Network) else "iptables"
    except ValueError:
        return None


class SandboxExecutor:
    _jobs: dict[str, dict] = {}
    _lock = threading.Lock()
    _counter = 0
    _networks: dict[str, str] = {}
    _net_lock = threading.Lock()
    _gw_lock = threading.Lock()
    _egress_created = False
    _egress_lock = threading.Lock()

    @classmethod
    def _docker_client(cls):
        return _docker_client(timeout=650)

    @classmethod
    def _network_name(cls, engagement_id: str) -> str:
        return f"{NETWORK_PREFIX}{engagement_id}"

    @classmethod
    def _gateway_name(cls, engagement_id: str) -> str:
        return f"{GATEWAY_PREFIX}{engagement_id}"

    @classmethod
    def _scope_version(cls, engagement_id: str) -> int | None:
        scope = storage.load_scope(engagement_id)
        if scope is None:
            return None
        return scope.get("version")

    @classmethod
    def _ensure_egress_network(cls) -> str:
        with cls._egress_lock:
            if cls._egress_created:
                return EGRESS_NET
            client = cls._docker_client()
            try:
                net = client.networks.get(EGRESS_NET)
                cls._egress_created = True
                return EGRESS_NET
            except NotFound:
                net = client.networks.create(
                    EGRESS_NET,
                    driver="bridge",
                    enable_ipv6=True,
                    check_duplicate=True,
                    options={"com.docker.network.bridge.enable_icc": "false"},
                    ipam=docker.types.IPAMConfig(
                        driver="default",
                        pool_configs=[
                            {"subnet": EGRESS_SUBNET_V4, "gateway": EGRESS_GATEWAY_V4},
                            {"subnet": EGRESS_SUBNET_V6, "gateway": EGRESS_GATEWAY_V6},
                        ],
                    ),
                    labels={"phase": "3-sandbox", "role": "egress"},
                )
                cls._egress_created = True
                return EGRESS_NET

    @classmethod
    def _lookup_gateway(cls, engagement_id: str) -> str | None:
        client = cls._docker_client()
        gw_name = cls._gateway_name(engagement_id)
        try:
            c = client.containers.get(gw_name)
            if c.status == "running":
                return c.id
            c.remove(force=True)
            return None
        except NotFound:
            return None

    @classmethod
    def _read_gw_state(cls) -> dict:
        with _gw_state_lock:
            try:
                return json.loads(_GW_STATE_PATH.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return {}

    @classmethod
    def _write_gw_state(cls, state: dict) -> None:
        with _gw_state_lock:
            _GW_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _GW_STATE_PATH.write_text(json.dumps(state, indent=2))

    @classmethod
    def _store_scope_version(cls, engagement_id: str, version: int | None) -> None:
        state = cls._read_gw_state()
        state[engagement_id] = {"scope_version": version}
        cls._write_gw_state(state)

    @classmethod
    def _get_stored_scope_version(cls, engagement_id: str) -> int | None:
        state = cls._read_gw_state()
        entry = state.get(engagement_id)
        if entry is not None:
            v = entry.get("scope_version")
            if v is not None:
                try:
                    return int(v)
                except (ValueError, TypeError):
                    return None
        return None

    @classmethod
    def ensure_network(cls, engagement_id: str) -> str:
        net_name = cls._network_name(engagement_id)
        subnet_v4 = _engagement_subnet(engagement_id)
        subnet_v6 = _engagement_subnet_v6(engagement_id)
        with cls._net_lock:
            if net_name in cls._networks:
                return net_name
            client = cls._docker_client()
            try:
                net = client.networks.get(net_name)
                cls._networks[net_name] = net.id
                return net_name
            except NotFound:
                bridge_ip_v4 = _bridge_ip_from_subnet(subnet_v4)
                bridge_ip_v6 = _bridge_ip_from_subnet_v6(subnet_v6)
                net = client.networks.create(
                    net_name,
                    driver="bridge",
                    internal=False,
                    enable_ipv6=True,
                    check_duplicate=True,
                    ipam=docker.types.IPAMConfig(
                        driver="default",
                        pool_configs=[
                            {"subnet": subnet_v4, "gateway": bridge_ip_v4},
                            {"subnet": subnet_v6, "gateway": bridge_ip_v6},
                        ],
                    ),
                    labels={"engagement_id": engagement_id, "phase": "3-sandbox"},
                )
                cls._networks[net_name] = net.id
                return net_name

    @classmethod
    def _ensure_gateway(cls, engagement_id: str) -> str:
        scope_ver = cls._scope_version(engagement_id)

        existing_id = cls._lookup_gateway(engagement_id)
        if existing_id is not None:
            stored_ver = cls._get_stored_scope_version(engagement_id)
            if stored_ver is not None and stored_ver == scope_ver:
                return existing_id
            if stored_ver != scope_ver:
                cls._sync_egress_rules_internal(engagement_id, existing_id, scope_ver)
                return existing_id

        with cls._gw_lock:
            existing_id = cls._lookup_gateway(engagement_id)
            if existing_id is not None:
                stored_ver = cls._get_stored_scope_version(engagement_id)
                if stored_ver is not None and stored_ver == scope_ver:
                    return existing_id
                if stored_ver != scope_ver:
                    cls._sync_egress_rules_internal(engagement_id, existing_id, scope_ver)
                    return existing_id

            net_name = cls.ensure_network(engagement_id)
            client = cls._docker_client()
            gw_name = cls._gateway_name(engagement_id)

            try:
                existing_c = client.containers.get(gw_name)
                existing_c.remove(force=True)
            except NotFound:
                pass

            subnet_v4 = _engagement_subnet(engagement_id)
            subnet_v6 = _engagement_subnet_v6(engagement_id)
            gw_ip_v4 = _gateway_ip_from_subnet(subnet_v4)
            gw_ip_v6 = _gateway_ip_from_subnet_v6(subnet_v6)

            cls._ensure_egress_network()

            container = client.containers.run(
                IMAGE_NAME,
                command=[
                    "sh", "-c",
                    "iptables -P FORWARD DROP && "
                    "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && "
                    "iptables -t nat -A POSTROUTING -j MASQUERADE && "
                    "ip6tables -P FORWARD DROP && "
                    "ip6tables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && "
                    "ip6tables -t nat -A POSTROUTING -j MASQUERADE && "
                    "sleep infinity"
                ],
                network=net_name,
                cap_add=["NET_ADMIN", "NET_RAW"],
                detach=True,
                mem_limit="256m",
                nano_cpus=int(1.0 * 1e9),
                name=gw_name,
                sysctls={
                    "net.ipv4.ip_forward": "1",
                    "net.ipv6.conf.all.forwarding": "1",
                },
                labels={
                    "engagement_id": engagement_id,
                    "role": "gateway",
                    "phase": "3-sandbox",
                    "redteam.scope_version": str(scope_ver) if scope_ver else "0",
                },
            )

            client.networks.get(EGRESS_NET).connect(container)

            if scope_ver:
                cls._sync_egress_rules_internal(engagement_id, container.id, scope_ver)

            return container.id

    @classmethod
    def _get_gateway_ip(cls, engagement_id: str) -> str:
        subnet = _engagement_subnet(engagement_id)
        return _gateway_ip_from_subnet(subnet)

    @classmethod
    def _get_gateway_ip_v6(cls, engagement_id: str) -> str:
        subnet = _engagement_subnet_v6(engagement_id)
        return _gateway_ip_from_subnet_v6(subnet)

    @classmethod
    def _sync_egress_rules_internal(cls, engagement_id: str, container_id: str, scope_ver: int) -> None:
        scope = storage.load_scope(engagement_id)
        if scope is None:
            return

        cls._exec_gw(container_id, ["iptables", "-F", "FORWARD"])
        cls._exec_gw(container_id, ["iptables", "-P", "FORWARD", "DROP"])
        cls._exec_gw(container_id, [
            "iptables", "-A", "FORWARD",
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ])
        cls._exec_gw(container_id, ["ip6tables", "-F", "FORWARD"])
        cls._exec_gw(container_id, ["ip6tables", "-P", "FORWARD", "DROP"])
        cls._exec_gw(container_id, [
            "ip6tables", "-A", "FORWARD",
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ])

        excluded = scope.get("excluded_targets", [])
        for excl in excluded:
            resolved = _resolve_target(excl)
            for ip_str in resolved:
                tbl = _ip_table_for(ip_str)
                if tbl is None:
                    continue
                cls._exec_gw(container_id, [tbl, "-A", "FORWARD", "-d", ip_str, "-j", "DROP"])

        targets = scope.get("targets", [])
        for target in targets:
            resolved = _resolve_target(target)
            for ip_str in resolved:
                tbl = _ip_table_for(ip_str)
                if tbl is None:
                    continue
                cls._exec_gw(container_id, [tbl, "-A", "FORWARD", "-d", ip_str, "-j", "ACCEPT"])

        cls._store_scope_version(engagement_id, scope_ver)

    @classmethod
    def sync_egress_rules(cls, engagement_id: str) -> None:
        scope_ver = cls._scope_version(engagement_id)
        if scope_ver is None:
            return

        cid = cls._lookup_gateway(engagement_id)
        if cid is None:
            return

        stored_ver = cls._get_stored_scope_version(engagement_id)
        if stored_ver == scope_ver:
            return

        cls._sync_egress_rules_internal(engagement_id, cid, scope_ver)

    @classmethod
    def _exec_gw(cls, container_id: str, cmd: list[str]) -> None:
        client = cls._docker_client()
        container = client.containers.get(container_id)
        exit_code, output = container.exec_run(cmd)
        if exit_code != 0:
            err = output.decode("utf-8", errors="replace").strip()
            raise ExecutorError(f"Gateway cmd {' '.join(cmd)} failed ({exit_code}): {err}")

    @classmethod
    def _fix_container_dns(cls, container, bridge_gw_v4: str) -> None:
        try:
            exit_code, output = container.exec_run(
                ["sh", "-c", r"sed -n 's/^# ExtServers: \[\(.*\)\]$/\1/p' /etc/resolv.conf"]
            )
            if exit_code != 0:
                return
            raw = output.decode("utf-8", errors="replace").strip()
            if not raw:
                return
            for part in raw.split(","):
                dns_ip = part.strip()
                if not dns_ip:
                    continue
                try:
                    ipaddress.ip_address(dns_ip)
                except ValueError:
                    continue
                container.exec_run(
                    ["ip", "route", "add", dns_ip, "via", bridge_gw_v4],
                    privileged=True,
                )
        except Exception:
            pass

    @classmethod
    def teardown_network(cls, engagement_id: str) -> None:
        gw_name = cls._gateway_name(engagement_id)
        client = cls._docker_client()
        try:
            c = client.containers.get(gw_name)
            c.remove(force=True)
        except (NotFound, DockerException):
            pass

        net_name = cls._network_name(engagement_id)
        with cls._net_lock:
            cls._networks.pop(net_name, None)
            try:
                net = client.networks.get(net_name)
                net.remove()
            except (NotFound, DockerException):
                pass

    @classmethod
    def _get_next_job_id(cls) -> str:
        # The in-memory counter resets on server restart and can collide with
        # run directories/output paths from a previous process (job IDs leaked
        # and were never cleaned up). Skip IDs whose run dir already exists so
        # a new job never overwrites another job's on-disk output.
        with cls._lock:
            while True:
                cls._counter += 1
                candidate = f"sbox-{cls._counter:04d}"
                if not (RUNS_DIR / candidate).exists():
                    return candidate

    @classmethod
    def _get_extra_caps(cls, tool_name: str | None) -> list[str]:
        caps = []
        if tool_name and tool_name in EXTRA_CAPS:
            caps.extend(EXTRA_CAPS[tool_name])
        return caps

    @classmethod
    def run(
        cls,
        engagement_id: str,
        command: list[str],
        *,
        tool_name: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        egress_restricted: bool = True,
    ) -> str:
        if not command:
            raise ExecutorError("Command list is empty")

        net_name = cls.ensure_network(engagement_id)
        job_id = cls._get_next_job_id()

        job_dir = RUNS_DIR / job_id / "output"
        job_dir.mkdir(parents=True, exist_ok=True)

        job = {
            "job_id": job_id,
            "engagement_id": engagement_id,
            "status": "queued",
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "findings": None,
            "output_file": str(job_dir),
            "tool_name": tool_name,
            "command": command,
            "started_at": None,
            "finished_at": None,
        }

        with cls._lock:
            cls._jobs[job_id] = job

        def _run_background():
            container = None
            client = cls._docker_client()
            try:
                with cls._lock:
                    cls._jobs[job_id]["status"] = "running"
                    cls._jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()

                cls._ensure_gateway(engagement_id)
                cls.sync_egress_rules(engagement_id)

                extra_caps = cls._get_extra_caps(tool_name)

                cmd_str = " ".join(shlex.quote(a) for a in command)
                wrapped_command = ["sh", "-c", cmd_str]

                volumes = {str(job_dir): {"bind": "/output", "mode": "rw"}}
                if _SUBFINDER_CONFIG.exists():
                    volumes[str(_SUBFINDER_CONFIG)] = {
                        "bind": "/root/.config/subfinder/provider-config.yaml",
                        "mode": "ro",
                    }

                container = client.containers.run(
                    IMAGE_NAME,
                    command=wrapped_command,
                    network=net_name,
                    remove=False,
                    detach=True,
                    mem_limit=DEFAULT_MEMORY,
                    nano_cpus=int(DEFAULT_CPUS * 1e9),
                    cap_drop=["ALL"],
                    cap_add=extra_caps if extra_caps else None,
                    working_dir="/output",
                    volumes=volumes,
                    labels={
                        "engagement_id": engagement_id,
                        "job_id": job_id,
                        "phase": "3-sandbox",
                    },
                )

                if egress_restricted:
                    bridge_gw_v4 = _bridge_ip_from_subnet(_engagement_subnet(engagement_id))
                    gateway_ip = cls._get_gateway_ip(engagement_id)
                    exec_id = client.api.exec_create(
                        container.id,
                        ["ip", "route", "replace", "default", "via", gateway_ip],
                        privileged=True,
                    )
                    client.api.exec_start(exec_id)

                    gateway_ip_v6 = cls._get_gateway_ip_v6(engagement_id)
                    exec_id_v6 = client.api.exec_create(
                        container.id,
                        ["ip", "-6", "route", "replace", "default", "via", gateway_ip_v6],
                        privileged=True,
                    )
                    client.api.exec_start(exec_id_v6)

                    cls._fix_container_dns(container, bridge_gw_v4)

                result = container.wait(timeout=timeout)

                logs_stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                logs_stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

                status_code = result.get("StatusCode", -1)

                findings = None
                if tool_name:
                    try:
                        tool_info = get_tool(tool_name)
                        parser_name = tool_info.get("output_parser")
                        if parser_name:
                            mod = __import__(f"tool_registry.parsers.{parser_name}", fromlist=["parse"])
                            findings = mod.parse(logs_stdout)
                    except Exception:
                        pass

                with cls._lock:
                    has_findings = findings and isinstance(findings, dict) and len(findings.get("findings", [])) > 0
                    cls._jobs[job_id]["status"] = "completed" if (status_code == 0 or has_findings) else "error"
                    cls._jobs[job_id]["stdout"] = logs_stdout
                    cls._jobs[job_id]["stderr"] = logs_stderr
                    cls._jobs[job_id]["exit_code"] = status_code
                    cls._jobs[job_id]["findings"] = findings
                    cls._jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

            except (docker.errors.APIError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                msg = str(e)
                if "Timeout" in msg or "timed out" in msg or "Read timed out" in msg:
                    with cls._lock:
                        cls._jobs[job_id]["status"] = "timeout"
                        cls._jobs[job_id]["exit_code"] = -1
                        cls._jobs[job_id]["stderr"] = f"Container timed out after {timeout}s"
                        cls._jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
                else:
                    with cls._lock:
                        cls._jobs[job_id]["status"] = "error"
                        cls._jobs[job_id]["stderr"] = msg
                        cls._jobs[job_id]["exit_code"] = -1
                        cls._jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                with cls._lock:
                    cls._jobs[job_id]["status"] = "error"
                    cls._jobs[job_id]["stderr"] = str(e)
                    cls._jobs[job_id]["exit_code"] = -1
                    cls._jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
            finally:
                if container:
                    try:
                        container.remove(force=True)
                    except Exception:
                        pass

        thread = threading.Thread(target=_run_background, daemon=True)
        thread.start()

        return job_id

    @classmethod
    def get_result(cls, job_id: str) -> dict | None:
        with cls._lock:
            return cls._jobs.get(job_id)


def _extract_host(value: str) -> str:
    if "://" in value:
        parsed = urlparse(value)
        hostname = parsed.hostname
        if hostname:
            return hostname
    return value


def execute_action(engagement_id: str, tool_name: str, params: dict) -> dict:
    scope = storage.load_scope(engagement_id)
    if scope is None:
        return {"error": f"Engagement '{engagement_id}' not found. Create a scope first."}

    try:
        tool = get_tool(tool_name)
    except ToolRegistryError as e:
        return {"error": str(e)}

    attack_class = tool.get("attack_class")
    if not attack_class:
        return {"error": f"Tool '{tool_name}' has no attack_class defined"}

    target = params.get("target", "")
    if not target:
        return {"error": "Missing required param: target"}

    scope_target = _extract_host(target)

    action = {
        "engagement_id": engagement_id,
        "target": scope_target,
        "attack_class": attack_class,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    result = validate_action(action, scope)
    if not result["allowed"]:
        return {"error": result["reason"]}

    risk_tier = tool.get("risk_tier", "active_scan")
    if risk_tier in ("active_scan", "exploit"):
        # Validate params before creating the approval. An approval with
        # params that fail build_command could never be executed at
        # approve-time and would sit stuck in pending forever.
        try:
            build_command(tool_name, params)
        except ToolRegistryError as e:
            return {"error": str(e)}

        approval = create_approval(
            engagement_id=engagement_id,
            tool_name=tool_name,
            params=params,
            risk_tier=risk_tier,
            attack_class=attack_class,
            target=target,
        )
        return {"status": "pending_approval", "approval_id": approval["approval_id"]}

    try:
        command = build_command(tool_name, params)
    except ToolRegistryError as e:
        return {"error": str(e)}

    egress_restricted = tool.get("egress_restricted", True)
    try:
        timeout = int(tool.get("timeout") or DEFAULT_TIMEOUT)
        job_id = SandboxExecutor.run(
            engagement_id=engagement_id,
            command=command,
            tool_name=tool_name,
            timeout=timeout,
            egress_restricted=egress_restricted,
        )
        return {"job_id": job_id}
    except ExecutorError as e:
        return {"error": str(e)}
    except (DockerException, ImageNotFound) as e:
        return {"error": f"Docker error: {e}"}


def _cleanup_dangling() -> None:
    """Remove dangling images and any leftover containers from previous failed builds."""
    client = _docker_client(timeout=30)
    for img in client.images.list(filters={"dangling": True}):
        try:
            client.images.remove(img.id, force=True)
        except Exception:
            pass
    for c in client.containers.list(all=True, filters={"name": "redteam-tools"}):
        try:
            c.remove(force=True)
        except Exception:
            pass


def _get_next_build_id() -> str:
    global _build_counter
    with _build_jobs_lock:
        _build_counter += 1
        return f"build-{_build_counter:04d}"


def build_image_async() -> str:
    """Start async Docker image build, return build_job_id immediately."""
    job_id = _get_next_build_id()

    job = {
        "build_job_id": job_id,
        "status": "building",
        "logs": [],
        "error": None,
        "image": IMAGE_NAME,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    }
    with _build_jobs_lock:
        _build_jobs[job_id] = job

    def _build_background():
        client = _docker_client(timeout=950)
        build_logs: list[str] = []
        try:
            _cleanup_dangling()

            dockerfile_path = Path(__file__).parent / "Dockerfile"
            if not dockerfile_path.exists():
                raise ExecutorError(f"Dockerfile not found at {dockerfile_path}")

            try:
                old = client.images.get(IMAGE_NAME)
                client.images.remove(old.id, force=True)
            except ImageNotFound:
                pass

            img_raw, logs = client.images.build(
                path=str(dockerfile_path.parent),
                dockerfile=str(dockerfile_path),
                tag=IMAGE_NAME,
                rm=True,
                forcerm=True,
                timeout=BUILD_TIMEOUT,
            )
            for log_chunk in logs:
                if isinstance(log_chunk, dict):
                    if "stream" in log_chunk:
                        line = log_chunk["stream"].rstrip("\n")
                        if line:
                            build_logs.append(line)
                    elif "error" in log_chunk:
                        raise ExecutorError(log_chunk["error"])
                    elif "errorDetail" in log_chunk:
                        detail = log_chunk["errorDetail"]
                        if isinstance(detail, dict):
                            raise ExecutorError(detail.get("message", str(detail)))
                        raise ExecutorError(str(detail))

            if img_raw is None or IMAGE_NAME not in (img_raw.tags or []):
                client.images.get(IMAGE_NAME)

            with _build_jobs_lock:
                _build_jobs[job_id]["status"] = "completed"
                _build_jobs[job_id]["logs"] = build_logs
                _build_jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

        except Exception as e:
            _cleanup_dangling()
            with _build_jobs_lock:
                _build_jobs[job_id]["status"] = "error"
                _build_jobs[job_id]["error"] = str(e)
                _build_jobs[job_id]["logs"] = build_logs
                _build_jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

    thread = threading.Thread(target=_build_background, daemon=True)
    thread.start()
    return job_id


def get_build_status(build_job_id: str) -> dict | None:
    with _build_jobs_lock:
        return _build_jobs.get(build_job_id)


def ensure_image_built() -> bool:
    """Synchronous fallback — only used internally, not from the API."""
    client = _docker_client(timeout=30)
    try:
        client.images.get(IMAGE_NAME)
        return True
    except ImageNotFound:
        pass
    try:
        job_id = build_image_async()
        for _ in range(BUILD_TIMEOUT * 2):
            status = get_build_status(job_id)
            if status and status["status"] in ("completed", "error"):
                return status["status"] == "completed"
            time.sleep(0.5)
        return False
    except Exception:
        return False
