from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scope_engine.router import router as scope_router
from tool_registry.router import router as tools_router
from sandbox_executor.router import router as sandbox_router
from approval_gate.router import router as approval_router
from orchestrator.router import router as orchestrator_router

app = FastAPI(title="AI Red Team Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:4173"],
    allow_origin_regex=r"http://localhost:51[0-9]{2}",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scope_router)
app.include_router(tools_router)
app.include_router(sandbox_router)
app.include_router(approval_router)
app.include_router(orchestrator_router)


@app.on_event("startup")
def _start_auto_drive():
    from orchestrator.engine import start_auto_continue_worker
    start_auto_continue_worker()


@app.get("/api/health")
def health():
    return {"status": "ok", "phase": "6-investigation"}
