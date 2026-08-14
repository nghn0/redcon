import time
import pytest
import docker
from docker.errors import NotFound

from sandbox_executor.executor import (
    SandboxExecutor,
    execute_action,
    _resolve_target,
    IMAGE_NAME,
)
from scope_engine import storage

ENG_1 = "iso-test-eng-1"
ENG_2 = "iso-test-eng-2"
ENG_EGRESS = "egress-test-eng"
NET_1 = SandboxExecutor._network_name(ENG_1)
NET_2 = SandboxExecutor._network_name(ENG_2)

SCANME_IP = "45.33.32.156"
SCANME_IPV6 = "2600:3c01::f03c:91ff:fe18:bb2f"
OUT_OF_SCOPE_IP = "1.1.1.1"
OUT_OF_SCOPE_IPV6 = "2606:4700:4700::1111"
ENG_IPV6 = "ipv6-test-eng"


def _cleanup():
    client = docker.from_env()
    for net_name in (NET_1, NET_2, SandboxExecutor._network_name(ENG_EGRESS)):
        try:
            net = client.networks.get(net_name)
            for c in net.containers:
                net.disconnect(c)
            net.remove()
        except (NotFound, docker.errors.APIError):
            pass
    for eng_id in (ENG_1, ENG_2, ENG_EGRESS, ENG_IPV6):
        try:
            SandboxExecutor.teardown_network(eng_id)
        except Exception:
            pass


def _ensure_scope(engagement_id: str, targets: list[str] | None = None,
                  excluded: list[str] | None = None):
    scope = storage.load_scope(engagement_id)
    if scope:
        return scope
    data = {
        "engagement_id": engagement_id,
        "engagement_name": f"Test {engagement_id}",
        "targets": targets or ["203.0.113.0/24", "test-target.local"],
        "excluded_targets": excluded or [],
        "start_time": "2026-01-01T00:00:00+00:00",
        "end_time": "2030-01-01T00:00:00+00:00",
        "allowed_attack_classes": ["recon", "web", "network"],
        "authorization_contact": {"name": "Tester", "email": "t@t.com", "role": "tester"},
        "emergency_contact": "tester",
        "rate_limit": None,
        "notify_before_exploit": False,
    }
    return storage.save_scope(data)


def _inject_route(container, gw_ip: str):
    """Inject IPv4 default route via privileged exec (no NET_ADMIN needed)."""
    exit_code, output = container.exec_run(
        ["ip", "route", "replace", "default", "via", gw_ip],
        privileged=True,
    )
    if exit_code != 0:
        raise RuntimeError(f"Route injection failed: {output.decode()}")


def _inject_route_v6(container, gw_ip_v6: str):
    """Inject IPv6 default route via privileged exec."""
    exit_code, output = container.exec_run(
        ["ip", "-6", "route", "replace", "default", "via", gw_ip_v6],
        privileged=True,
    )
    if exit_code != 0:
        raise RuntimeError(f"IPv6 route injection failed: {output.decode()}")


@pytest.fixture(scope="module", autouse=True)
def setup():
    _cleanup()
    _ensure_scope(ENG_1)
    _ensure_scope(ENG_2)
    _ensure_scope(ENG_EGRESS,
                  targets=[SCANME_IP, "203.0.113.0/24"],
                  excluded=["203.0.113.5"])
    _ensure_scope(ENG_IPV6,
                  targets=[SCANME_IP, SCANME_IPV6, "2001:db8::/32"],
                  excluded=["2001:db8::5"])
    yield
    _cleanup()


class TestResolveTarget:
    def test_resolves_ip(self):
        assert _resolve_target("1.2.3.4") == ["1.2.3.4"]

    def test_resolves_cidr(self):
        assert _resolve_target("10.0.0.0/24") == ["10.0.0.0/24"]

    def test_resolves_domain(self):
        ips = _resolve_target("scanme.nmap.org")
        assert len(ips) > 0
        assert SCANME_IP in ips

    def test_returns_empty_for_invalid(self):
        assert _resolve_target("") == []
        assert _resolve_target("  ") == []
        assert _resolve_target("not-a-domain-at-all-12345") == []


class TestIsolation:
    def test_1_cannot_reach_host(self):
        net = SandboxExecutor.ensure_network(ENG_1)
        SandboxExecutor._ensure_gateway(ENG_1)
        gw_ip = SandboxExecutor._get_gateway_ip(ENG_1)
        SandboxExecutor.sync_egress_rules(ENG_1)

        client = docker.from_env()
        container = client.containers.run(
            IMAGE_NAME,
            command=["sh", "-c",
                     "sleep 0.3; "
                     "curl -s --connect-timeout 3 http://10.0.0.1:8000/ 2>&1 || echo 'HOST_UNREACHABLE'"],
            network=net,
            detach=True,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        _inject_route(container, gw_ip)
        container.wait(timeout=15)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        container.remove(force=True)
        assert "HOST_UNREACHABLE" in output or "couldn't connect" in output or "timed out" in output, \
            f"Host was reachable through gateway! Output: {output}"

    def test_2_cross_engagement_isolated(self):
        net1 = SandboxExecutor.ensure_network(ENG_1)
        net2 = SandboxExecutor.ensure_network(ENG_2)
        SandboxExecutor._ensure_gateway(ENG_2)
        gw2_ip = SandboxExecutor._get_gateway_ip(ENG_2)
        SandboxExecutor.sync_egress_rules(ENG_2)

        client = docker.from_env()
        container1 = client.containers.run(
            IMAGE_NAME,
            command=["sleep", "30"],
            network=net1,
            detach=True,
            remove=False,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        try:
            container1.reload()
            ip1 = container1.attrs["NetworkSettings"]["Networks"][NET_1]["IPAddress"]

            container = client.containers.run(
                IMAGE_NAME,
                command=["sh", "-c",
                         "sleep 0.3; "
                         "ping -c 1 -W 2 " + ip1 + " 2>&1 || echo 'UNREACHABLE'"],
                network=net2,
                detach=True,
                cap_drop=["ALL"],
                cap_add=["NET_RAW"],
                mem_limit="128m",
            )
            _inject_route(container, gw2_ip)
            container.wait(timeout=15)
            output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            container.remove(force=True)
            assert "UNREACHABLE" in output or "100% packet loss" in output, \
                f"Cross-network reachable! Output: {output}"
        finally:
            try:
                container1.remove(force=True)
            except Exception:
                pass

    def test_3_out_of_scope_target_blocked_by_gateway(self):
        net = SandboxExecutor._network_name(ENG_EGRESS)
        SandboxExecutor.ensure_network(ENG_EGRESS)
        SandboxExecutor._ensure_gateway(ENG_EGRESS)
        gw_ip = SandboxExecutor._get_gateway_ip(ENG_EGRESS)
        SandboxExecutor.sync_egress_rules(ENG_EGRESS)

        client = docker.from_env()
        container = client.containers.run(
            IMAGE_NAME,
            command=["sh", "-c",
                     "sleep 0.3; "
                     "curl -s --connect-timeout 5 http://" + OUT_OF_SCOPE_IP + "/ 2>&1 || echo 'BLOCKED'"],
            network=net,
            detach=True,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        _inject_route(container, gw_ip)
        container.wait(timeout=15)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        container.remove(force=True)
        assert "BLOCKED" in output or "timed out" in output or "couldn't connect" in output, \
            f"Out-of-scope target {OUT_OF_SCOPE_IP} was reachable through gateway! Output: {output}"

    def test_4_in_scope_external_target_reachable_through_gateway(self):
        net = SandboxExecutor._network_name(ENG_EGRESS)
        SandboxExecutor.ensure_network(ENG_EGRESS)
        SandboxExecutor._ensure_gateway(ENG_EGRESS)
        gw_ip = SandboxExecutor._get_gateway_ip(ENG_EGRESS)
        SandboxExecutor.sync_egress_rules(ENG_EGRESS)

        client = docker.from_env()
        container = client.containers.run(
            IMAGE_NAME,
            command=["sh", "-c",
                     "sleep 0.3; "
                     "curl -s --connect-timeout 15 http://" + SCANME_IP + "/ 2>&1 || echo 'FAILED'"],
            network=net,
            detach=True,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        _inject_route(container, gw_ip)
        container.wait(timeout=25)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        container.remove(force=True)
        assert "FAILED" not in output and "timed out" not in output, \
            f"In-scope target {SCANME_IP} was NOT reachable through gateway! Output: {output}"

    def test_5_excluded_target_blocked_within_allowed_cidr(self):
        net = SandboxExecutor._network_name(ENG_EGRESS)
        SandboxExecutor.ensure_network(ENG_EGRESS)
        SandboxExecutor._ensure_gateway(ENG_EGRESS)
        gw_ip = SandboxExecutor._get_gateway_ip(ENG_EGRESS)
        SandboxExecutor.sync_egress_rules(ENG_EGRESS)

        client = docker.from_env()
        container = client.containers.run(
            IMAGE_NAME,
            command=["sh", "-c",
                     "sleep 0.3; "
                     "curl -s --connect-timeout 5 http://203.0.113.5/ 2>&1 || echo 'BLOCKED'"],
            network=net,
            detach=True,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        _inject_route(container, gw_ip)
        container.wait(timeout=15)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        container.remove(force=True)
        assert "BLOCKED" in output or "timed out" in output, \
            f"Excluded target 203.0.113.5 was reachable! Output: {output}"

    def test_6_timeout_kills_container(self):
        client = docker.from_env()
        import requests
        container = client.containers.run(
            IMAGE_NAME,
            command=["sleep", "60"],
            network="none",
            detach=True,
            remove=False,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        timed_out = False
        try:
            container.wait(timeout=5)
        except requests.exceptions.ReadTimeout:
            timed_out = True
        except Exception as e:
            if "Timeout" in str(e) or "timed out" in str(e):
                timed_out = True
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass
        assert timed_out, "Container was not killed by timeout — wait() returned without timeout"

    def test_7_output_only_in_mounted_dir(self):
        net = SandboxExecutor.ensure_network(ENG_1)
        client = docker.from_env()

        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            client.containers.run(
                IMAGE_NAME,
                command=[
                    "sh", "-c",
                    "echo 'inside-output' > /output/test_out.txt; "
                    "echo 'outside-attempt' > /tmp/outside.txt"
                ],
                network=net,
                remove=True,
                cap_drop=["ALL"],
                mem_limit="128m",
                working_dir="/output",
                volumes={tmpdir: {"bind": "/output", "mode": "rw"}},
            )

            out_file = os.path.join(tmpdir, "test_out.txt")
            assert os.path.isfile(out_file), "Output file 'test_out.txt' NOT found in mounted /output"

            content = open(out_file).read().strip()
            assert content == "inside-output", f"Output content mismatch: {content}"

            outside_file = os.path.join(tmpdir, "..", "outside.txt")
            assert not os.path.isfile(outside_file), "File written to /tmp appeared on host — only /output visible"


    def test_8_ipv6_in_scope_target_reachable_through_gateway(self):
        net = SandboxExecutor._network_name(ENG_IPV6)
        SandboxExecutor.ensure_network(ENG_IPV6)
        SandboxExecutor._ensure_gateway(ENG_IPV6)
        gw_ip = SandboxExecutor._get_gateway_ip(ENG_IPV6)
        gw_ip_v6 = SandboxExecutor._get_gateway_ip_v6(ENG_IPV6)
        SandboxExecutor.sync_egress_rules(ENG_IPV6)

        client = docker.from_env()
        container = client.containers.run(
            IMAGE_NAME,
            command=["sh", "-c",
                     "sleep 0.5; "
                     "curl -6 -s --connect-timeout 15 http://["
                     + SCANME_IPV6 + "]/ 2>&1 || echo 'FAILED'"],
            network=net,
            detach=True,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        _inject_route(container, gw_ip)
        _inject_route_v6(container, gw_ip_v6)
        container.wait(timeout=25)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        container.remove(force=True)
        assert "FAILED" not in output and "timed out" not in output, \
            f"IPv6 in-scope target {SCANME_IPV6} was NOT reachable! Output: {output}"

    def test_9_ipv6_out_of_scope_target_blocked_by_gateway(self):
        net = SandboxExecutor._network_name(ENG_IPV6)
        SandboxExecutor.ensure_network(ENG_IPV6)
        SandboxExecutor._ensure_gateway(ENG_IPV6)
        gw_ip = SandboxExecutor._get_gateway_ip(ENG_IPV6)
        gw_ip_v6 = SandboxExecutor._get_gateway_ip_v6(ENG_IPV6)
        SandboxExecutor.sync_egress_rules(ENG_IPV6)

        client = docker.from_env()
        container = client.containers.run(
            IMAGE_NAME,
            command=["sh", "-c",
                     "sleep 0.5; "
                     "curl -6 -s --connect-timeout 10 http://["
                     + OUT_OF_SCOPE_IPV6 + "]/ 2>&1 || echo 'BLOCKED'"],
            network=net,
            detach=True,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        _inject_route(container, gw_ip)
        _inject_route_v6(container, gw_ip_v6)
        container.wait(timeout=20)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        container.remove(force=True)
        assert "BLOCKED" in output or "timed out" in output, \
            f"IPv6 out-of-scope target {OUT_OF_SCOPE_IPV6} was reachable! Output: {output}"

    def test_10_ipv6_excluded_target_blocked_within_allowed_cidr(self):
        net = SandboxExecutor._network_name(ENG_IPV6)
        SandboxExecutor.ensure_network(ENG_IPV6)
        SandboxExecutor._ensure_gateway(ENG_IPV6)
        gw_ip = SandboxExecutor._get_gateway_ip(ENG_IPV6)
        gw_ip_v6 = SandboxExecutor._get_gateway_ip_v6(ENG_IPV6)
        SandboxExecutor.sync_egress_rules(ENG_IPV6)

        gw_id = SandboxExecutor._lookup_gateway(ENG_IPV6)
        rules_out = docker.from_env().containers.get(gw_id).exec_run(
            ["ip6tables", "-L", "FORWARD", "-v"]
        )
        rules_text = rules_out.output.decode("utf-8", errors="replace")

        assert "2001:db8::5" in rules_text and "DROP" in rules_text, \
            f"Excluded target 2001:db8::5 not in ip6tables DROP rules:\n{rules_text}"
        cidr_idx = rules_text.find("2001:db8::/32")
        excl_idx = rules_text.find("2001:db8::5")
        assert excl_idx < cidr_idx, \
            "Excluded DROP rule must appear before CIDR ACCEPT rule in ip6tables"

        client = docker.from_env()
        container = client.containers.run(
            IMAGE_NAME,
            command=["sh", "-c",
                     "sleep 0.5; "
                     "curl -6 -s --connect-timeout 5 http://[2001:db8::5]/ 2>&1 || echo 'BLOCKED'"],
            network=net,
            detach=True,
            cap_drop=["ALL"],
            mem_limit="128m",
        )
        _inject_route(container, gw_ip)
        _inject_route_v6(container, gw_ip_v6)
        container.wait(timeout=15)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        container.remove(force=True)
        assert "BLOCKED" in output or "timed out" in output, \
            f"Excluded IPv6 target 2001:db8::5 was reachable! Output: {output}"

    def test_11_resolves_aaaa_records_for_domains(self):
        ips = _resolve_target("scanme.nmap.org")
        assert SCANME_IPV6 in ips, \
            f"scanme.nmap.org AAAA record {SCANME_IPV6} not in resolved IPs: {ips}"
        assert SCANME_IP in ips, \
            f"scanme.nmap.org A record {SCANME_IP} not in resolved IPs: {ips}"

    def test_12_resolves_ipv6_literal(self):
        assert _resolve_target("::1") == ["::1"]
        assert _resolve_target("2001:db8::1") == ["2001:db8::1"]

    def test_13_resolves_ipv6_cidr(self):
        assert _resolve_target("2001:db8::/32") == ["2001:db8::/32"]
        assert _resolve_target("fd00::/8") == ["fd00::/8"]


class TestValidators:
    def test_validate_url_ipv6(self):
        from tool_registry.validators import validate_url
        assert validate_url("http://[::1]:8080/path") is True
        assert validate_url("http://[2001:db8::1]/") is True
        assert validate_url("http://[2600:3c01::f03c:91ff:fe18:bb2f]:80/") is True
        assert validate_url("http://[::1]") is True
        assert validate_url("http://[2001:db8::1]:80") is True

    def test_validate_url_ipv4_still_works(self):
        from tool_registry.validators import validate_url
        assert validate_url("http://1.2.3.4/") is True
        assert validate_url("http://1.2.3.4:8080/path") is True
        assert validate_url("http://example.com/") is True

    def test_validate_url_ipv6_invalid(self):
        from tool_registry.validators import validate_url
        assert validate_url("http://[::1") is False
        assert validate_url("http://::1]/") is False
        assert validate_url("http://[xyz::1]/") is False
        assert validate_url("http://[not-an-ip]/") is False


class TestExecuteAction:
    def test_scope_denies_out_of_scope(self):
        result = execute_action("nonexistent-eng", "nmap", {"target": "10.0.0.1"})
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_scope_denies_attack_class(self):
        _ensure_scope("test-class-eng")
        result = execute_action("test-class-eng", "hydra",
                                {"target": "127.0.0.1", "username_list": "/tmp/u.txt",
                                 "password_list": "/tmp/p.txt", "service": "ssh"})
        if "error" in result:
            assert any(kw in result["error"].lower()
                       for kw in ["scope", "class", "not found", "attack class"])

    def test_execute_action_correct_flow(self):
        _ensure_scope("test-flow-eng")
        result = execute_action("test-flow-eng", "nmap", {"target": "test-target.local", "ports": "80"})
        assert "error" not in result or result.get("error") is None or "not in" not in result.get("error", "")
        if "job_id" in result:
            job = SandboxExecutor.get_result(result["job_id"])
            assert job is not None

    def test_active_scan_with_invalid_params_rejected_before_approval(self):
        _ensure_scope("test-flow-eng")
        result = execute_action("test-flow-eng", "nikto", {"target": "http://test-target.local"})
        assert "error" in result
        assert "pending_approval" not in result
