import { useState, useEffect } from 'react';
import {
  listEngagements,
  listTools,
  executeAction,
  buildToolCommand,
  getSandboxJobStatus,
  getImageStatus,
  buildImage,
  getBuildStatus,
  getApproval,
  type EngagementSummary,
  type ToolInfo,
  type BuildStatus,
} from '../hooks/useApi';
import {
  BoxIcon,
  CpuIcon,
  AlertIcon,
  PlayIcon,
  CheckCircleIcon,
  XIcon,
  ClockIcon,
  ActivityIcon,
  TerminalIcon,
} from './icons';

export function SandboxPanel() {
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [selectedEngagement, setSelectedEngagement] = useState('');
  const [selectedTool, setSelectedTool] = useState('');
  const [paramValues, setParamValues] = useState<Record<string, string>>({});
  const [submitLoading, setSubmitLoading] = useState(false);
  const [imageStatus, setImageStatus] = useState<'loading' | 'ready' | 'not_found'>('loading');
  const [imageBuilding, setImageBuilding] = useState(false);
  const [buildStatus, setBuildStatus] = useState<BuildStatus | null>(null);
  const [result, setResult] = useState<{
    jobId?: string;
    error?: string;
    status?: string;
    stdout?: string;
    stderr?: string;
    exitCode?: number | null;
    findings?: { tool: string; findings: Array<{ type: string; detail: Record<string, unknown> }> } | null;
  } | null>(null);

  const [pendingApproval, setPendingApproval] = useState<{
    approvalId: string;
    status: string;
  } | null>(null);

  const [confirming, setConfirming] = useState<{
    tool: ToolInfo;
    params: Record<string, string>;
    command: string[] | null;
    error: string;
  } | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  async function fetchData() {
    setLoading(true);
    setError('');
    try {
      const [engs, tls, img] = await Promise.all([
        listEngagements(),
        listTools(),
        getImageStatus().catch(() => ({ status: 'not_found' })),
      ]);
      setEngagements(engs);
      setTools(tls);
      setImageStatus(img.status as 'ready' | 'not_found');
      if (engs.length > 0) setSelectedEngagement(engs[0].engagement_id);
    } catch (e: any) {
      setError(e.message || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  }

  const selected = tools.find(t => t.name === selectedTool);

  function handleParamChange(key: string, value: string) {
    setConfirming(null);
    setParamValues(prev => ({ ...prev, [key]: value }));
  }

  async function handleBuildImage() {
    setImageBuilding(true);
    setBuildStatus(null);
    try {
      const res = await buildImage();
      setBuildStatus({ ...res, logs: [] });

      const interval = setInterval(async () => {
        try {
          const status = await getBuildStatus(res.build_job_id);
          setBuildStatus(status);
          if (status.status === 'completed') {
            clearInterval(interval);
            setImageBuilding(false);
            setImageStatus('ready');
          } else if (status.status === 'error') {
            clearInterval(interval);
            setImageBuilding(false);
            setImageStatus('not_found');
          }
        } catch {
          clearInterval(interval);
          setImageBuilding(false);
          setImageStatus('not_found');
        }
      }, 2000);
    } catch {
      setImageBuilding(false);
      setImageStatus('not_found');
    }
  }

  async function handleSubmit() {
    if (!selectedEngagement || !selectedTool || !selected) return;
    setResult(null);
    setPendingApproval(null);

    // Merge tool defaults with whatever the user typed, then stop and show a
    // confirmation card before anything executes. The user must explicitly
    // accept these params (or go back and change them). Proving the command
    // also validates the params against the registry before execution.
    const merged = { ...(selected.defaults || {}), ...paramValues };

    let command: string[] | null = null;
    let error = '';
    try {
      const built = await buildToolCommand(selected.name, merged);
      command = built.command;
    } catch (e: any) {
      error = e.message || 'Invalid parameters';
    }

    setConfirming({ tool: selected, params: merged, command, error });
  }

  async function handleConfirmExecute() {
    if (!confirming) return;
    const { tool, params } = confirming;
    setConfirming(null);
    setSubmitLoading(true);
    setResult(null);
    setPendingApproval(null);
    try {
      const res = await executeAction({
        engagement_id: selectedEngagement,
        tool_name: tool.name,
        params,
      });
      if (res.error) {
        setResult({ error: res.error });
        setSubmitLoading(false);
      } else if (res.status === 'pending_approval' && res.approval_id) {
        setPendingApproval({ approvalId: res.approval_id, status: 'pending' });
        setSubmitLoading(false);
        pollApproval(res.approval_id);
      } else if (res.job_id) {
        setResult({ jobId: res.job_id, status: 'queued' });
        pollJob(res.job_id);
      }
    } catch (e: any) {
      setResult({ error: e.message || 'Execution failed' });
      setSubmitLoading(false);
    }
  }

  function pollApproval(approvalId: string) {
    const interval = setInterval(async () => {
      try {
        const approval = await getApproval(approvalId);
        if (approval.status === 'approved' && approval.result_job_id) {
          clearInterval(interval);
          setPendingApproval({ approvalId, status: 'approved' });
          setResult({ jobId: approval.result_job_id, status: 'queued' });
          pollJob(approval.result_job_id);
        } else if (approval.status === 'denied' || approval.status === 'expired') {
          clearInterval(interval);
          setPendingApproval({ approvalId, status: approval.status });
          setSubmitLoading(false);
        }
      } catch {
        clearInterval(interval);
        setSubmitLoading(false);
      }
    }, 2000);
  }

  function pollJob(jobId: string) {
    const interval = setInterval(async () => {
      try {
        const status = await getSandboxJobStatus(jobId);
        if (status.status === 'completed' || status.status === 'error' || status.status === 'timeout') {
          clearInterval(interval);
          setSubmitLoading(false);
          setResult({
            jobId,
            status: status.status,
            stdout: status.stdout || '',
            stderr: status.stderr || '',
            exitCode: status.exit_code,
            findings: status.findings || null,
          });
        } else if (status.status === 'running' || status.status === 'queued') {
          setResult({ jobId, status: status.status });
        }
      } catch {
        clearInterval(interval);
        setSubmitLoading(false);
      }
    }, 1500);
  }

  if (loading) return <div className="loading">Loading engagements &amp; tools…</div>;
  if (error) return (
    <div className="error-box">
      <AlertIcon />
      <span>{error}</span>
    </div>
  );

  const statusLabel =
    result?.status === 'queued' ? 'Queued' :
    result?.status === 'running' ? 'Running' :
    result?.status === 'completed' ? 'Completed' :
    result?.status === 'timeout' ? 'Timed Out' :
    result?.status ? result.status : '—';

  return (
    <div className="sandbox-panel">
      <div className="section-head">
        <div>
          <h1>Sandbox Executor</h1>
          <p className="section-desc">
            Execute vetted tools inside an isolated, per-engagement Docker container. All actions
            are scope-validated; active-scan and exploit tools require human approval.
          </p>
        </div>
      </div>

      <div className="docker-image-bar">
        <CpuIcon style={{ width: 17, height: 17, color: imageStatus === 'ready' ? 'var(--accent-success)' : 'var(--accent-danger)' }} />
        {imageStatus === 'loading' ? (
          <span className="text-muted">Checking Docker image…</span>
        ) : imageStatus === 'ready' ? (
          <span className="docker-image-ready">Docker Image Running</span>
        ) : (
          <>
            <span className="docker-image-missing">Docker Image Not Found</span>
            <button className="btn btn-secondary btn-sm" onClick={handleBuildImage} disabled={imageBuilding} style={{ marginLeft: 'auto' }}>
              {imageBuilding ? (
                <>
                  <span className="spinner" />
                  Building…
                </>
              ) : (
                <>
                  <BoxIcon />
                  Create Docker Image
                </>
              )}
            </button>
          </>
        )}
      </div>

      {buildStatus && (
        <div className="sandbox-result" style={{ marginBottom: 16 }}>
          <div className="terminal">
            <div className="terminal-header">
              <span className="terminal-dots"><span /><span /><span /></span>
              <span className="terminal-title">build {buildStatus.build_job_id}</span>
              <span className={`badge ${buildStatus.status === 'completed' ? 'badge-success' : buildStatus.status === 'error' ? 'badge-danger' : 'badge-blue'}`} style={{ marginLeft: 'auto', fontSize: 10 }}>
                {buildStatus.status.toUpperCase()}
              </span>
            </div>
            {buildStatus.error && (
              <div className="terminal-body err">{buildStatus.error}</div>
            )}
            {buildStatus.logs && buildStatus.logs.length > 0 && (
              <div className="terminal-body" style={{ maxHeight: 220 }}>
                {buildStatus.logs.join('\n')}
              </div>
            )}
            {buildStatus.status === 'building' && (
              <div className="loading" style={{ padding: 12, fontSize: 12 }}>
                <span className="spinner" /> Building Docker image (this may take several minutes)…
              </div>
            )}
          </div>
        </div>
      )}

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">
            <PlayIcon />
            Execute Tool in Isolated Sandbox
          </span>
        </div>
        <div className="card-body">
          <div className="form-row">
            <div className="form-group flex-1">
              <label htmlFor="sb-engagement">Engagement</label>
              <select
                id="sb-engagement"
                className="input"
                value={selectedEngagement}
                onChange={e => {
                  setSelectedEngagement(e.target.value);
                  setResult(null);
                  setPendingApproval(null);
                }}
              >
                {engagements.map(e => (
                  <option key={e.engagement_id} value={e.engagement_id}>
                    {e.engagement_name} ({e.engagement_id})
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group flex-1">
              <label htmlFor="sb-tool">Tool</label>
              <select
                id="sb-tool"
                className="input"
                value={selectedTool}
                onChange={e => {
                  const newTool = e.target.value;
                  setSelectedTool(newTool);
                  const tool = tools.find(t => t.name === newTool);
                  setParamValues(tool?.defaults ? { ...tool.defaults } : {});
                  setResult(null);
                  setPendingApproval(null);
                }}
              >
                <option value="">-- Select a tool --</option>
                {tools.map(t => (
                  <option key={t.name} value={t.name}>
                    {t.name} {t.installed ? '' : '(not installed)'}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {selected && (
            <div style={{ marginTop: 18 }}>
              <div className="form-section-title">
                Params for {selected.name}
                <span className="label-hint"> ({selected.risk_tier} / {selected.attack_class})</span>
              </div>
              <div className="param-list">
                {Object.entries(selected.allowed_params).map(([key, ptype]) => (
                  <div key={key} className="param-row">
                    <span className="param-label">
                      {key} <span className="text-muted">({ptype})</span>
                    </span>
                    <input
                      type="text"
                      className="input mono"
                      placeholder={key}
                      value={paramValues[key] || ''}
                      onChange={e => handleParamChange(key, e.target.value)}
                    />
                  </div>
                ))}
              </div>

              <button
                className="btn btn-primary"
                onClick={handleSubmit}
                disabled={submitLoading || !selectedEngagement}
                style={{ marginTop: 14 }}
              >
                {submitLoading ? (
                  <>
                    <span className="spinner" />
                    Executing…
                  </>
                ) : (
                  <>
                    <TerminalIcon />
                    Execute
                  </>
                )}
              </button>
            </div>
          )}

          {!selected && (
            <div className="empty" style={{ marginTop: 16, padding: '32px 24px' }}>
              <span className="empty-icon">
                <BoxIcon />
              </span>
              <div className="empty-title">Select an engagement and tool</div>
              <div className="empty-desc">Choose a tool to execute a scope-validated action.</div>
            </div>
          )}
        </div>
      </div>

          {confirming && (
            <div className="sandbox-result" style={{ marginTop: 16 }}>
              <div className="confirm-card">
                <div className="confirm-head">
                  <span className="confirm-title">Confirm params for {confirming.tool.name}</span>
                  <span className={`badge ${confirming.command ? 'badge-blue' : 'badge-danger'}`} style={{ fontSize: 10 }}>
                    {confirming.command ? 'VALID' : 'INVALID'}
                  </span>
                </div>
                <p className="text-muted" style={{ fontSize: 12, margin: '4px 0 10px' }}>
                  These are the params that will be used. <span className="default-pill">DEFAULT</span> means the value
                  comes from the tool registry defaults — you can keep it or override it below.
                </p>
                <div className="param-list">
                  {Object.keys(confirming.tool.allowed_params).map(key => {
                    const toolDefault = confirming.tool.defaults?.[key];
                    const value = confirming.params[key] ?? '';
                    const isDefault = toolDefault !== undefined && value === String(toolDefault);
                    return (
                      <div key={key} className="param-row">
                        <span className="param-label">
                          {key}
                          {isDefault ? (
                            <span className="default-pill">DEFAULT</span>
                          ) : (
                            <span className="custom-pill">CUSTOM</span>
                          )}
                        </span>
                        <input
                          type="text"
                          className="input mono"
                          placeholder={key}
                          value={value}
                          onChange={e => {
                            const next = { ...confirming.params, [key]: e.target.value };
                            setConfirming({ ...confirming, params: next, error: '' });
                            setParamValues(prev => ({ ...prev, [key]: e.target.value }));
                          }}
                        />
                      </div>
                    );
                  })}
                </div>
                {confirming.command && confirming.command.length > 0 && (
                  <div className="terminal" style={{ marginTop: 12 }}>
                    <div className="terminal-header">
                      <span className="terminal-dots"><span /><span /><span /></span>
                      <span className="terminal-title">command</span>
                    </div>
                    <div className="terminal-body mono" style={{ fontSize: 12 }}>
                      {confirming.command.join(' ')}
                    </div>
                  </div>
                )}
                {confirming.error && (
                  <div className="error-box" style={{ marginTop: 12 }}>
                    <AlertIcon />
                    <span>{confirming.error}</span>
                  </div>
                )}
                <div className="confirm-actions">
                  <button
                    className="btn btn-primary"
                    onClick={handleConfirmExecute}
                    disabled={submitLoading || !confirming.command}
                    style={{ marginTop: 14 }}
                  >
                    {submitLoading ? (
                      <>
                        <span className="spinner" />
                        Executing…
                      </>
                    ) : (
                      <>
                        <TerminalIcon />
                        Execute with these params
                      </>
                    )}
                  </button>
                  <button
                    className="btn btn-secondary"
                    onClick={() => setConfirming(null)}
                    disabled={submitLoading}
                    style={{ marginTop: 14 }}
                  >
                    Change params
                  </button>
                </div>
              </div>
            </div>
          )}

          {pendingApproval && (
        <div className="sandbox-result">
          <div className={`alert ${pendingApproval.status === 'approved' ? 'alert-success' : pendingApproval.status === 'denied' || pendingApproval.status === 'expired' ? 'alert-danger' : 'alert-warning'}`}>
            {pendingApproval.status === 'pending' ? <ClockIcon /> : pendingApproval.status === 'approved' ? <CheckCircleIcon /> : <XIcon />}
            <div>
              <strong className="mono">{pendingApproval.approvalId}</strong>
              {' — '}
              {pendingApproval.status === 'pending'
                ? 'Waiting for human approval — check the Approvals tab to approve or deny'
                : pendingApproval.status === 'denied'
                  ? 'This action was denied'
                  : pendingApproval.status === 'expired'
                    ? 'This approval request expired — submit a new action'
                    : 'Approved'}
            </div>
          </div>
        </div>
      )}

      {result && (
        <div className="sandbox-result">
          {result.error && (
            <div className="error-box">
              <AlertIcon />
              <span>{result.error}</span>
            </div>
          )}

          {result.jobId && !result.error && (
            <div className="terminal">
              <div className="terminal-header">
                <span className="terminal-dots"><span /><span /><span /></span>
                <span className="terminal-title mono">{result.jobId}</span>
                <span
                  className={`badge ${result.status === 'completed' ? 'badge-success' : result.status === 'running' || result.status === 'queued' ? 'badge-blue' : 'badge-danger'}`}
                  style={{ marginLeft: 'auto', fontSize: 10 }}
                >
                  {statusLabel.toUpperCase()}
                </span>
              </div>
              {(result.status === 'queued' || result.status === 'running') && (
                <div className="loading" style={{ padding: 14, fontSize: 12 }}>
                  <ActivityIcon style={{ width: 14, height: 14, verticalAlign: -2, marginRight: 6, animation: 'pulse 1.2s infinite' }} />
                  Job in progress…
                </div>
              )}
              {result.stdout && (
                <div className="terminal-body">{result.stdout}</div>
              )}
              {result.stderr && (
                <div className="terminal-body err">{result.stderr}</div>
              )}
              {result.findings && (
                <details className="summary-card" style={{ margin: '10px 12px' }}>
                  <summary>Findings ({result.findings.tool})</summary>
                  <pre className="command-preview" style={{ border: 'none' }}>
                    {JSON.stringify(result.findings, null, 2)}
                  </pre>
                </details>
              )}
              {result.exitCode !== null && result.exitCode !== undefined && (
                <div className="terminal-header" style={{ borderTop: '1px solid var(--border)', borderBottom: 'none' }}>
                  <span className="terminal-title">exit code</span>
                  <span className={`mono ${result.exitCode === 0 ? 'status-green' : 'status-red'}`} style={{ marginLeft: 'auto' }}>
                    {result.exitCode}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
