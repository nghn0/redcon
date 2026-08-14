# REDCON — AI Red Team Platform

> **Status: Still under development.** This is an experimental/alpha build. APIs, the UI, and the investigation loop are actively changing and may break between commits. Use only against systems you own or have explicit written authorization to test.

REDCON is an **AI-driven, scope-enforced red team / pentest orchestration platform**. You give it an authorized target (an *engagement scope*), and its AI assistant plans and runs reconnaissance, scanning, and validation actions against that target — automatically, but never outside your authorization.

```
┌──────────────────────────────────────────────────────────────────────┐
│  FRONTEND (React + Vite, :5173)                                      │
│  Scope · Tool Registry · Sandbox · Approvals · AI Assistant           │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ REST (FastAPI :8000)
┌──────────────────────────────▼───────────────────────────────────────┐
│  BACKEND (FastAPI)                                                   │
│  ├── Scope Engine     → engagements, targets, exclusions, validation │
│  ├── Tool Registry    → capabilities → tools (nmap, nuclei, hydra…)  │
│  ├── Approval Gate    → human approval for active_scan / exploit     │
│  ├── Sandbox Executor → isolated Docker runs, egress-restricted      │
│  └── Orchestrator     → AI investigation loop (Observe→Analyze→Plan→Select) │
│                        LLM via Ollama (:11434)                       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ docker
┌──────────────────────────────▼───────────────────────────────────────┐
│  Docker · redteam-tools:latest image (nmap, nuclei, subfinder, …)     │
│  Per-engagement isolated network + egress gateway with iptables       │
│  (outbound traffic allowed ONLY to in-scope targets)                  │
└──────────────────────────────────────────────────────────────────────┘
```

## How the system works

1. **Scope Engine** — You register an *engagement*: targets, excluded targets, allowed attack classes, time window, contacts. Every action REDCON wants to run is validated against this scope first.
2. **Tool Registry** — A capability catalog maps high-level needs (e.g. *subdomain enumeration*) to real tools (`subfinder`, `nuclei`, `nmap`, `gobuster`, `nikto`, `sqlmap`, `hydra`), with command templates, parameter validation, and output parsers that turn raw tool output into structured findings.
3. **Sandbox Executor** — Every tool runs inside an **ephemeral Docker container** built from the `redteam-tools:latest` image. Each engagement gets an isolated network with an egress gateway. The gateway runs iptables rules so containers can only reach targets that are **in scope** — anything else is dropped. Scans are capped by memory/CPU/timeout, and all output is captured and parsed.
4. **Approval Gate** — `active_scan` and `exploit` tier actions (nuclei, gobuster, nikto, sqlmap, hydra…) never run without a **human approving** them in the UI. Passive recon (nmap, subfinder) runs automatically.
5. **Orchestrator (AI Assistant)** — An LLM (via Ollama) drives an autonomous investigation loop: **Observe → Analyze → Plan → Select**. It reads the blackboard of confirmed facts, hypotheses, and open unknowns, then *proposes* the next action. You confirm the parameters in the UI, it executes in the sandbox, findings are fed back into the blackboard, and the loop continues automatically until it reports the engagement as complete.

## Prerequisites

| Dependency | Why | Check |
|---|---|---|
| **Ollama** | Local LLM for the AI assistant | `ollama list` |
| **Docker** | Runs the sandbox tool containers | `docker info` |
| **Python 3.11+** | Backend (FastAPI) | `python3 --version` |
| **Node.js 18+** | Frontend (Vite/React) | `node --version` |

---

## 1 · Ollama — local LLM model

The orchestrator talks to any **OpenAI-compatible** endpoint. Default is Ollama, running locally in the background on `http://127.0.0.1:11434`.

### Install Ollama

- **macOS** — download **Ollama.app** from https://ollama.com/download, or:
  ```bash
  brew install ollama
  ```
- **Linux**
  ```bash
  curl -fsSL https://ollama.com/install.sh | sh
  ```

### Download a local model

```bash
ollama pull qwen2.5-coder:7b
```

> Any model works. 7B “coder” models give the best tool-call/JSON reliability on a laptop; smaller models (e.g. `qwen2.5-coder:3b`) are faster but sloppier at choosing tools.

### Keep it running in the background

- **macOS (Homebrew)** — starts Ollama as a background service and keeps it running across reboots:
  ```bash
  brew services start ollama
  ```
- **macOS (Ollama.app)** — just launch the app; it runs as a background menu-bar process.
- **Linux** — the install script registers a systemd service:
  ```bash
  sudo systemctl enable ollama
  sudo systemctl start ollama
  ```
  Or run it manually in the background:
  ```bash
  nohup ollama serve > /tmp/ollama.log 2>&1 &
  ```

### Verify it is up

```bash
ollama list
curl http://127.0.0.1:11434/api/tags
```

Both should respond with your downloaded model.

---

## 2 · Docker

### Install

- **macOS** — install **Docker Desktop** (https://www.docker.com/products/docker-desktop/) and open it. It runs as a background service.
- **Linux** — install the Docker Engine + `docker compose` plugin via your distro's package manager.

### Keep it running & verify

Docker Desktop starts in the background automatically. Confirm the daemon is reachable:

```bash
docker info
docker run --rm hello-world   # sanity check
```

> The backend auto-detects the Docker socket (`/var/run/docker.sock` or `~/.docker/run/docker.sock`).

---

## 3 · Backend (FastAPI)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn httpx "docker" requests pyyaml
```

Configure the LLM endpoint and model:

```bash
cp .env.example .env
# edit .env to match your Ollama model, e.g.
#   LLM_API_BASE=http://127.0.0.1:11434/v1
#   LLM_MODEL=qwen2.5-coder:7b
```

Start the API:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Verify:

```bash
curl http://localhost:8000/api/health
curl http://localhost:8000/api/orchestrator/health   # should show connected + model available
```

---

## 4 · Frontend (React)

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** — you should see the REDCON dashboard with the **Backend** health dot green.

---

## 5 · Build the sandbox Docker image (first run)

The sandbox needs the **`redteam-tools:latest`** image (Ubuntu base + nmap, nuclei, subfinder, gobuster, nikto, hydra, sqlmap, SecLists wordlists). Build it once — it takes a few minutes.

**Via the UI (recommended):**

1. Open the **Sandbox** tab.
2. Check **Image Status** — it will show `not_found`.
3. Click **Build Image**.
4. Watch the status turn **building → running** (image `redteam-tools:latest` ready). The image is now running/available for all sandbox jobs.

**Via CLI (equivalent):**

```bash
docker build -t redteam-tools:latest backend/sandbox_executor/
```

Verify it exists:

```bash
docker images | grep redteam-tools
```

> Note: the sandbox image needs to support **IPv6** bridge networks and `iptables` (used by the egress gateway). Docker Desktop handles this out of the box.

---

## Using REDCON

1. **New Scope** → create an engagement with your authorized target(s) and exclusions.
2. **Scope Viewer / Validate** → inspect the engagement and test whether a proposed action would be allowed.
3. **Tool Registry** → see which capabilities are available and their install status.
4. **Sandbox** → build the image and run individual tools manually against a scope.
5. **Approvals** → approve/deny the high-risk actions waiting for human review.
6. **AI Assistant** → start an orchestrator session for an engagement, describe your goal (e.g. *“enumerate subdomains and find web vulnerabilities on target.com”*), and let the loop propose, you confirm, it scans, and it keeps going — until it decides the engagement is complete.

## Project layout

```
backend/
  main.py                     # FastAPI app (CORS, routers, auto-drive worker)
  scope_engine/               # engagements, scope validation & storage
  tool_registry/              # capability catalog, tools.yaml, command builders, parsers
  sandbox_executor/           # Docker executor, egress gateway, Dockerfile, image build
  approval_gate/              # human approval workflow for high-risk actions
  orchestrator/               # LLM client, investigation loop (analyst/planner/selector)
  tests/                      # pytest suite per module
frontend/
  src/components/             # Scope, ToolRegistry, Sandbox, Approvals, Orchestrator panels
  src/hooks/useApi.ts         # typed API client (localhost:8000)
```

## Security & authorization

- Every execution is validated against the engagement scope; the sandbox egress gateway **drops** traffic to anything out of scope.
- `active_scan` / `exploit` actions require explicit human approval.
- Use only on targets you own or have written authorization for. REDCON is a pentest/security-research tool.

## Roadmap

- [ ] Stable `v1` API surface & persistence
- [ ] More tools / parsers in the registry
- [ ] Frontend polish and multi-engagement dashboards
- [ ] Reporting (findings → structured report export)

---
*Still under development — expect breaking changes.*