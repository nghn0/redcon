const API_BASE = 'http://localhost:8000/api/scope';

export interface EngagementSummary {
  engagement_id: string;
  engagement_name: string;
  version: number;
  start_time: string;
  end_time: string;
}

export interface ScopeData {
  engagement_id: string;
  engagement_name: string;
  version: number;
  targets: string[];
  excluded_targets: string[];
  start_time: string;
  end_time: string;
  allowed_attack_classes: string[];
  authorization_contact: {
    name: string;
    email: string;
    role: string;
  };
  emergency_contact: string;
  rate_limit: number | null;
  notify_before_exploit: boolean | null;
  created_at: string;
}

export interface ValidationResult {
  allowed: boolean;
  reason: string;
}

export interface VersionInfo {
  version: number;
  file: string;
  created_at: number;
}

export async function createScope(data: Partial<ScopeData>): Promise<ScopeData> {
  const res = await fetch(`${API_BASE}/engagements`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail?.[0]?.msg || JSON.stringify(err.detail) || 'Failed to create scope');
  }
  return res.json();
}

export async function listEngagements(): Promise<EngagementSummary[]> {
  const res = await fetch(`${API_BASE}/engagements`);
  if (!res.ok) throw new Error('Failed to fetch engagements');
  return res.json();
}

export async function getScope(engagementId: string, version?: number): Promise<ScopeData> {
  const params = version ? `?version=${version}` : '';
  const res = await fetch(`${API_BASE}/engagements/${engagementId}${params}`);
  if (!res.ok) throw new Error('Engagement not found');
  return res.json();
}

export async function getVersions(engagementId: string): Promise<VersionInfo[]> {
  const res = await fetch(`${API_BASE}/engagements/${engagementId}/versions`);
  if (!res.ok) throw new Error('Failed to fetch versions');
  return res.json();
}

export interface ValidateAction {
  engagement_id: string;
  target: string;
  attack_class: string;
  timestamp: string;
}

export async function validateAction(action: ValidateAction): Promise<ValidationResult> {
  const res = await fetch(`${API_BASE}/validate?engagement_id=${action.engagement_id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(action),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Validation failed');
  }
  return res.json();
}

// === Tool Registry API ===

const TOOLS_API = 'http://localhost:8000/api/tools';

export interface ToolInfo {
  name: string;
  risk_tier: 'passive' | 'active_scan' | 'exploit';
  attack_class: string;
  description: string;
  command_template: string[];
  allowed_params: Record<string, string>;
  required_params: string[];
  defaults?: Record<string, string>;
  output_parser: string;
  binary_name: string;
  install_command: string;
  installed: boolean;
}

export interface BuildCommandResult {
  tool_name: string;
  command: string[];
}

export interface InstallResult {
  success: boolean;
  output: string;
  installed: boolean;
}

export interface RunResult {
  job_id: string;
}

export interface JobStatus {
  status: string;
  stdout: string;
  stderr: string;
  exit_code: number | null;
  findings?: { tool: string; findings: Array<{ type: string; detail: Record<string, unknown> }> };
}

export async function listTools(): Promise<ToolInfo[]> {
  const res = await fetch(`${TOOLS_API}`);
  if (!res.ok) throw new Error('Failed to fetch tools');
  return res.json();
}

export async function getTool(toolName: string): Promise<ToolInfo> {
  const res = await fetch(`${TOOLS_API}/${toolName}`);
  if (!res.ok) throw new Error('Tool not found');
  return res.json();
}

export async function buildToolCommand(toolName: string, params: Record<string, string>): Promise<BuildCommandResult> {
  const res = await fetch(`${TOOLS_API}/build-command`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool_name: toolName, params }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Command build failed');
  }
  return res.json();
}

export async function installTool(toolName: string): Promise<InstallResult> {
  const res = await fetch(`${TOOLS_API}/${toolName}/install`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Install failed');
  }
  return res.json();
}

export async function deleteTool(toolName: string): Promise<InstallResult> {
  const res = await fetch(`${TOOLS_API}/${toolName}/delete`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Delete failed');
  }
  return res.json();
}

export async function runTool(toolName: string, params: Record<string, string>): Promise<RunResult> {
  const res = await fetch(`${TOOLS_API}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool_name: toolName, params }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Run failed');
  }
  return res.json();
}

export async function getRunResult(jobId: string): Promise<JobStatus> {
  const res = await fetch(`${TOOLS_API}/run/${jobId}`);
  if (!res.ok) throw new Error('Job not found');
  return res.json();
}

// === Sandbox Executor API ===

const SANDBOX_API = 'http://localhost:8000/api';

export interface ExecuteRequest {
  engagement_id: string;
  tool_name: string;
  params: Record<string, string>;
}

export interface ExecuteResult {
  job_id?: string;
  error?: string;
  status?: string;
  approval_id?: string;
}

export interface SandboxJobStatus {
  job_id: string;
  engagement_id: string | null;
  status: string | null;
  stdout: string | null;
  stderr: string | null;
  exit_code: number | null;
  findings: { tool: string; findings: Array<{ type: string; detail: Record<string, unknown> }> } | null;
  output_file: string | null;
  command: string[] | null;
  started_at: string | null;
  finished_at: string | null;
}

export async function executeAction(req: ExecuteRequest): Promise<ExecuteResult> {
  const res = await fetch(`${SANDBOX_API}/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Execution denied');
  }
  return res.json();
}

export async function getSandboxJobStatus(jobId: string): Promise<SandboxJobStatus> {
  const res = await fetch(`${SANDBOX_API}/execute/${jobId}`);
  if (!res.ok) throw new Error('Job not found');
  return res.json();
}

export async function getImageStatus(): Promise<{ status: string; image: string }> {
  const res = await fetch(`${SANDBOX_API}/execute/image-status`);
  return res.json();
}

export interface BuildStatus {
  build_job_id: string;
  status: string;
  logs: string[];
  error: string | null;
  image: string;
  started_at: string | null;
  finished_at: string | null;
}

export async function buildImage(): Promise<BuildStatus> {
  const res = await fetch(`${SANDBOX_API}/execute/build-image`, { method: 'POST' });
  if (!res.ok) throw new Error('Image build failed');
  return res.json();
}

export async function getBuildStatus(buildJobId: string): Promise<BuildStatus> {
  const res = await fetch(`${SANDBOX_API}/execute/build-status/${buildJobId}`);
  if (!res.ok) throw new Error('Build job not found');
  return res.json();
}

// === Approval Gate API ===

const APPROVALS_API = 'http://localhost:8000/api/approvals';

export interface ApprovalRequest {
  approval_id: string;
  engagement_id: string;
  tool_name: string;
  params: Record<string, string>;
  risk_tier: string;
  attack_class: string;
  target: string;
  requested_at: string;
  status: string;
  decided_by: string | null;
  decided_at: string | null;
  deny_reason: string | null;
  result_job_id: string | null;
}

export interface ApproveResult {
  status: string;
  job_id: string | null;
  approval_id: string;
}

export async function listApprovals(engagementId?: string): Promise<ApprovalRequest[]> {
  let url = `${APPROVALS_API}`;
  if (engagementId) {
    url += `?engagement_id=${encodeURIComponent(engagementId)}`;
  }
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch approvals');
  return res.json();
}

export async function getApproval(approvalId: string): Promise<ApprovalRequest> {
  const res = await fetch(`${APPROVALS_API}/${approvalId}`);
  if (!res.ok) throw new Error('Approval not found');
  return res.json();
}

export async function approveApproval(approvalId: string): Promise<ApproveResult> {
  const res = await fetch(`${APPROVALS_API}/${approvalId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decided_by: 'ui-user' }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Approval failed');
  }
  return res.json();
}

export async function denyApproval(approvalId: string, reason = ''): Promise<ApprovalRequest> {
  const res = await fetch(`${APPROVALS_API}/${approvalId}/deny`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason, decided_by: 'ui-user' }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Deny failed');
  }
  return res.json();
}

// === Orchestrator API ===

const ORCHESTRATOR_API = 'http://localhost:8000/api/orchestrator';

export interface OrchestratorState {
  session_id: string;
  engagement_id: string;
  goal: string;
  status: string;
  summary: string | null;
  findings_so_far: Array<{ type: string; detail: Record<string, unknown>; _tool?: string }>;
  tools_already_run: string[];
  action_history: Array<{
    type?: string;
    tool_name?: string;
    params?: Record<string, string>;
    target?: string;
    outcome?: string;
    approval_id?: string;
    job_id?: string;
    reason?: string;
    content?: string;
    timestamp: string;
  }>;
  pending_or_denied: Array<{
    tool_name: string;
    target: string;
    outcome: string;
    approval_id?: string;
    reason?: string;
  }>;
  pending_param_confirm?: {
    tool_name: string;
    params: Record<string, string>;
    action_kind?: 'install' | 'execute';
    capability?: string;
    install_command?: string;
    verification_command?: string;
    requirements?: string[];
  } | null;
  created_at: string;
  updated_at: string;
}

export interface OrchestratorSession {
  session_id: string;
  engagement_id: string;
  goal: string;
  status: string;
  created_at: string;
  updated_at: string;
  action_count: number;
  finding_count: number;
}

export async function createOrchestratorSession(
  engagementId: string,
  goal: string,
): Promise<OrchestratorState> {
  const res = await fetch(`${ORCHESTRATOR_API}/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ engagement_id: engagementId, goal }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to create session');
  }
  return res.json();
}

export async function sendOrchestratorMessage(
  sessionId: string,
  message: string,
): Promise<OrchestratorState> {
  const res = await fetch(`${ORCHESTRATOR_API}/sessions/${sessionId}/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to send message');
  }
  return res.json();
}

export async function getOrchestratorSession(
  sessionId: string,
): Promise<OrchestratorState> {
  const res = await fetch(`${ORCHESTRATOR_API}/sessions/${sessionId}`);
  if (!res.ok) throw new Error('Session not found');
  return res.json();
}

export async function listOrchestratorSessions(): Promise<OrchestratorSession[]> {
  const res = await fetch(`${ORCHESTRATOR_API}/sessions`);
  if (!res.ok) throw new Error('Failed to fetch sessions');
  return res.json();
}

export async function checkOrchestratorLLM(): Promise<{ connected: boolean; model: string; error?: string }> {
  const res = await fetch(`${ORCHESTRATOR_API}/health`);
  if (!res.ok) throw new Error('LLM health check failed');
  return res.json();
}

export async function confirmOrchestratorParams(
  sessionId: string,
  params: Record<string, string>,
): Promise<OrchestratorState> {
  const res = await fetch(`${ORCHESTRATOR_API}/sessions/${sessionId}/params-confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ params }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to confirm params');
  }
  return res.json();
}

export async function cancelOrchestratorParams(sessionId: string): Promise<OrchestratorState> {
  const res = await fetch(`${ORCHESTRATOR_API}/sessions/${sessionId}/params-cancel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to cancel action');
  }
  return res.json();
}
