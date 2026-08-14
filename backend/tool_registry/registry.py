import os
import shutil
import subprocess
import threading
import yaml
from pathlib import Path

from .validators import VALIDATORS

TOOLS_YAML = Path(__file__).parent / "tools.yaml"

SAFE_TARGETS = {
    "localhost",
    "127.0.0.1",
    "::1",
}

NMAP_ONLY_SAFE_TARGETS = {
    "scanme.nmap.org",
}


class ToolRegistryError(Exception):
    pass


class UnknownToolError(ToolRegistryError):
    def __init__(self, tool_name: str):
        super().__init__(f"Unknown tool: '{tool_name}' — must be one of the 7 registered tools")


class UnknownParamError(ToolRegistryError):
    def __init__(self, tool_name: str, param: str):
        super().__init__(f"Unknown param '{param}' for tool '{tool_name}'")


class MissingRequiredParamError(ToolRegistryError):
    def __init__(self, tool_name: str, param: str):
        super().__init__(f"Missing required param '{param}' for tool '{tool_name}'")


class ParamValidationError(ToolRegistryError):
    def __init__(self, tool_name: str, param: str, value: str, param_type: str):
        super().__init__(
            f"Param '{param}' = '{value}' is not a valid {param_type} for tool '{tool_name}'"
        )


class SafeTargetRestrictionError(ToolRegistryError):
    def __init__(self, target: str):
        super().__init__(
            f"Execution restricted to safe test targets until Sandbox Executor (Phase 3) "
            f"provides isolation. Target '{target}' is not in the allow-list."
        )


def _load_registry() -> list[dict]:
    with open(TOOLS_YAML) as f:
        return yaml.safe_load(f)


def _find_tool(tool_name: str) -> dict | None:
    registry = _load_registry()
    for t in registry:
        if t["name"] == tool_name:
            return t
    return None


def get_all_tools() -> list[dict]:
    return _load_registry()


def get_capabilities() -> list[str]:
    """Registry-derived capability catalog; never duplicate this in planners.

    A capability is only advertised when at least one registered tool can
    fulfil it. New tools must declare their ``capabilities``; the planner and
    the LLM reason only over this set.
    """
    return sorted({c for tool in _load_registry() for c in tool.get("capabilities", [])})


def get_capability_requirements(capability: str) -> list[str]:
    """Minimum host requirements any resolver must satisfy before a tool that
    advertises this capability may be chosen. Capability-level requirements
    default to empty; tools may add their own stricter ones."""
    return [
        req
        for tool in _load_registry()
        if capability in tool.get("capabilities", [])
        for req in tool.get("requirements", [])
    ]


def get_tool_requirements(tool_name: str) -> list[str]:
    """Requirements a host must satisfy for ``tool_name`` to be healthy."""
    tool = get_tool(tool_name)
    return list(tool.get("requirements", []))


def get_tool(tool_name: str) -> dict:
    tool = _find_tool(tool_name)
    if tool is None:
        raise UnknownToolError(tool_name)
    return tool


def _get_fallback_bin_dirs() -> list[str]:
    dirs = [
        os.path.expanduser("~/go/bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ]
    gopath = os.environ.get("GOPATH")
    if gopath:
        dirs.append(os.path.join(gopath, "bin"))
    return [d for d in dirs if d]


def is_tool_installed(tool_name: str) -> bool:
    return _find_binary(tool_name) is not None


def is_tool_healthy(tool_name: str) -> bool:
    """A tool is healthy when its binary exists AND its verification command
    runs successfully. Compared to ``is_tool_installed`` this catches a broken
    install (e.g. missing shared library) so the resolver can avoid it."""
    if not is_tool_installed(tool_name):
        return False
    return verify_tool(tool_name)


def _find_binary(tool_name: str) -> str | None:
    tool = get_tool(tool_name)
    binary = tool["binary_name"]

    found = shutil.which(binary)
    if found:
        return found

    for d in _get_fallback_bin_dirs():
        p = os.path.join(d, binary)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p

    return None


def build_command(tool_name: str, params: dict) -> list[str]:
    tool = get_tool(tool_name)

    defaults = tool.get("defaults", {})
    params = {**defaults, **params}

    required = set(tool.get("required_params", list(tool["allowed_params"].keys())))
    allowed = set(tool["allowed_params"].keys())
    param_types = tool["allowed_params"]

    for key in params:
        if key not in allowed:
            raise UnknownParamError(tool_name, key)

    for req in required:
        if req not in params or params[req] is None or str(params[req]).strip() == "":
            raise MissingRequiredParamError(tool_name, req)

    template = list(tool["command_template"])
    result = []
    for i, part in enumerate(template):
        if part.startswith("{") and part.endswith("}"):
            key = part[1:-1]
            value = params.get(key, "")
            str_value = str(value).strip()

            if str_value == "" and key not in required:
                if result and result[-1].startswith("-"):
                    result.pop()
                continue

            if key in param_types:
                ptype = param_types[key]
                validator = VALIDATORS.get(ptype)
                if validator and not validator(str_value):
                    raise ParamValidationError(tool_name, key, str_value, ptype)

            result.append(str_value)
        else:
            result.append(part)

    return result


_run_jobs: dict[str, dict] = {}
_job_lock = threading.Lock()
_job_counter = 0


def _get_next_job_id() -> str:
    global _job_counter
    with _job_lock:
        _job_counter += 1
        return f"job-{_job_counter:04d}"


def _is_safe_target(tool_name: str, target: str) -> bool:
    t = target.strip()
    if t in SAFE_TARGETS:
        return True
    if t in NMAP_ONLY_SAFE_TARGETS and tool_name == "nmap":
        return True
    return False


def run_tool(tool_name: str, params: dict) -> str:
    tool = get_tool(tool_name)

    cmd = build_command(tool_name, params)

    target = params.get("target", "")
    if not _is_safe_target(tool_name, str(target).strip()):
        raise SafeTargetRestrictionError(str(target))

    job_id = _get_next_job_id()
    _run_jobs[job_id] = {"status": "running", "stdout": "", "stderr": "", "exit_code": None, "tool": tool_name}

    def _run():
        env = _augmented_env()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                env=env,
            )
            _run_jobs[job_id]["stdout"] = proc.stdout
            _run_jobs[job_id]["stderr"] = proc.stderr
            _run_jobs[job_id]["exit_code"] = proc.returncode
            _run_jobs[job_id]["status"] = "completed"

            parser_name = tool.get("output_parser")
            if parser_name:
                try:
                    mod = __import__(f"tool_registry.parsers.{parser_name}", fromlist=["parse"])
                    findings = mod.parse(proc.stdout)
                    _run_jobs[job_id]["findings"] = findings
                except Exception:
                    pass

        except subprocess.TimeoutExpired:
            _run_jobs[job_id]["status"] = "timeout"
            _run_jobs[job_id]["exit_code"] = -1
        except Exception as e:
            _run_jobs[job_id]["status"] = "error"
            _run_jobs[job_id]["stderr"] = str(e)
            _run_jobs[job_id]["exit_code"] = -1

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return job_id


def get_run_result(job_id: str) -> dict | None:
    return _run_jobs.get(job_id)


_DEPENDENCY_HINTS = {
    "go": "Install Go first from https://go.dev/dl/ or with 'brew install go', then retry",
    "brew": "Install Homebrew first from https://brew.sh/, then retry",
    "pip": "Install pip first (it usually comes with Python), then retry",
    "pip3": "Install pip first (it usually comes with Python), then retry",
}


def _missing_dependency_error(tool_name: str, cmd: list[str]) -> str:
    if cmd:
        dep = cmd[0]
        hint = _DEPENDENCY_HINTS.get(dep, f"'{dep}' is not installed or not on PATH")
        return f"Cannot install {tool_name}: requires '{dep}' which is not found on this system. {hint}."
    return f"Cannot install {tool_name}: the install command requires a dependency that is not installed."


def _augmented_env() -> dict:
    env = os.environ.copy()
    extra = _get_fallback_bin_dirs()
    env["PATH"] = ":".join(extra + [env.get("PATH", "")])
    return env


def install_tool(tool_name: str) -> dict:
    tool = get_tool(tool_name)

    if is_tool_installed(tool_name):
        return {"success": True, "output": f"Tool '{tool_name}' is already installed", "installed": True}

    cmd_str = tool["install_command"]
    cmd = cmd_str.split()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            env=_augmented_env(),
        )
        installed = is_tool_installed(tool_name)
        output = proc.stdout + proc.stderr
        if installed:
            binary_path = _find_binary(tool_name)
            if binary_path and not shutil.which(tool["binary_name"]):
                output += f"\n\nBinary installed at {binary_path}. Add ~/go/bin to your PATH to use this tool from the terminal, or use the Run button which handles PATH automatically."
        verified = verify_tool(tool_name) if installed else False
        return {"success": installed and verified, "output": output, "installed": installed, "verified": verified}
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "Installation timed out", "installed": False}
    except FileNotFoundError:
        return {"success": False, "output": _missing_dependency_error(tool_name, cmd), "installed": False}
    except Exception as e:
        return {"success": False, "output": str(e), "installed": False}


def verify_tool(tool_name: str) -> bool:
    """Verify a registered binary after installation without using a shell."""
    tool = get_tool(tool_name)
    binary = _find_binary(tool_name)
    if not binary:
        return False
    verification = tool.get("verification_command", "").split()
    if not verification:
        return True
    verification[0] = binary
    try:
        subprocess.run(verification, capture_output=True, text=True, timeout=30, env=_augmented_env())
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def delete_tool(tool_name: str) -> dict:
    tool = get_tool(tool_name)
    binary_name = tool["binary_name"]

    if not is_tool_installed(tool_name):
        return {"success": True, "output": f"Tool '{tool_name}' is not installed", "installed": False}

    binary_path = _find_binary(tool_name)

    if binary_name in ("nmap", "nikto", "hydra"):
        cmd = ["brew", "uninstall", binary_name]
    elif binary_name == "sqlmap":
        cmd = ["pip", "uninstall", "sqlmap", "-y"]
    else:
        cmd = ["rm", "-f", binary_path]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env=_augmented_env(),
        )
        still_installed = is_tool_installed(tool_name)
        output = proc.stdout + proc.stderr
        return {"success": not still_installed, "output": output, "installed": still_installed}
    except FileNotFoundError:
        return {"success": False, "output": _missing_dependency_error(tool_name, cmd), "installed": True}
    except Exception as e:
        return {"success": False, "output": str(e), "installed": True}
