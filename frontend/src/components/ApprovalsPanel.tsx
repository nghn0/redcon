import { useState, useEffect, useRef } from 'react';
import {
  listApprovals,
  approveApproval,
  denyApproval,
  getSandboxJobStatus,
  type ApprovalRequest,
  type SandboxJobStatus,
} from '../hooks/useApi';
import {
  ShieldIcon,
  FilterIcon,
  XIcon,
  AlertIcon,
  ClockIcon,
  CheckIcon,
} from './icons';

export function ApprovalsPanel() {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<{ id: string; text: string } | null>(null);
  const [jobResult, setJobResult] = useState<{ approvalId: string; job: SandboxJobStatus } | null>(null);
  const [filterTier, setFilterTier] = useState('');
  const pollRef = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());

  useEffect(() => {
    fetchApprovals();
    const interval = setInterval(fetchApprovals, 5000);
    return () => {
      clearInterval(interval);
      pollRef.current.forEach(clearInterval);
    };
  }, []);

  async function fetchApprovals() {
    try {
      const data = await listApprovals();
      setApprovals(data);
      setError('');
    } catch (e: any) {
      setError(e.message || 'Failed to load approvals');
    } finally {
      setLoading(false);
    }
  }

  function pollJob(approvalId: string, jobId: string) {
    if (pollRef.current.has(approvalId)) return;
    const interval = setInterval(async () => {
      try {
        const status = await getSandboxJobStatus(jobId);
        if (status.status === 'completed' || status.status === 'error' || status.status === 'timeout') {
          clearInterval(interval);
          pollRef.current.delete(approvalId);
          setJobResult({ approvalId, job: status });
          setActionLoading(null);
        }
      } catch {
        clearInterval(interval);
        pollRef.current.delete(approvalId);
      }
    }, 1500);
    pollRef.current.set(approvalId, interval);
  }

  async function handleApprove(approval: ApprovalRequest) {
    setActionLoading(approval.approval_id);
    setActionMsg(null);
    setJobResult(null);
    try {
      const result = await approveApproval(approval.approval_id);
      setActionMsg({ id: approval.approval_id, text: `Approved — job ${result.job_id || 'starting...'}` });
      if (result.job_id) {
        pollJob(approval.approval_id, result.job_id);
      }
      fetchApprovals();
    } catch (e: any) {
      setActionMsg({ id: approval.approval_id, text: `Error: ${e.message}` });
      setActionLoading(null);
    }
  }

  async function handleDeny(approval: ApprovalRequest) {
    setActionLoading(approval.approval_id);
    setActionMsg(null);
    try {
      const reason = window.prompt('Reason for denying (optional):', '');
      if (reason === null) {
        setActionLoading(null);
        return;
      }
      await denyApproval(approval.approval_id, reason || '');
      setActionMsg({ id: approval.approval_id, text: 'Denied' });
      fetchApprovals();
    } catch (e: any) {
      setActionMsg({ id: approval.approval_id, text: `Error: ${e.message}` });
    } finally {
      setActionLoading(null);
    }
  }

  const filtered = filterTier
    ? approvals.filter(a => a.risk_tier === filterTier)
    : approvals;

  const pendingCount = approvals.filter(a => a.status === 'pending').length;

  if (loading) return <div className="loading">Loading approvals…</div>;

  const statusBadge = (status: string) =>
    status === 'pending' ? 'badge-warning' :
    status === 'approved' ? 'badge-success' :
    status === 'denied' ? 'badge-danger' :
    'badge-neutral';

  return (
    <div className="approvals-panel">
      <div className="section-head">
        <div>
          <h1>Approval Gate</h1>
          <p className="section-desc">
            Human-in-the-loop control. Passive actions auto-approve; active-scan and exploit
            actions wait here for explicit approval before any container starts.
          </p>
        </div>
        <div className="section-head-actions">
          <span className="badge badge-warning">
            <ClockIcon style={{ width: 12, height: 12 }} />
            {pendingCount} pending
          </span>
        </div>
      </div>

      <div className="toolbar">
        <FilterIcon style={{ width: 15, height: 15, color: 'var(--text-muted)' }} />
        <label htmlFor="approval-filter">Risk tier:</label>
        <select
          id="approval-filter"
          className="input"
          value={filterTier}
          onChange={e => setFilterTier(e.target.value)}
        >
          <option value="">All tiers</option>
          <option value="passive">Passive</option>
          <option value="active_scan">Active Scan</option>
          <option value="exploit">Exploit</option>
        </select>
        <span className="toolbar-count">{filtered.length} shown</span>
      </div>

      {error && (
        <div className="error-box">
          <AlertIcon />
          <span>{error}</span>
        </div>
      )}

      {filtered.length === 0 && !error && (
        <div className="empty">
          <span className="empty-icon">
            <ShieldIcon />
          </span>
          <div className="empty-title">No approval requests</div>
          <div className="empty-desc">
            {filterTier
              ? 'No requests match the selected risk tier.'
              : 'Pending actions will appear here for review.'}
          </div>
        </div>
      )}

      <div className="approvals-list">
        {filtered.map(approval => (
          <div
            key={approval.approval_id}
            className="approval-card"
            style={{
              borderColor:
                approval.status === 'pending' ? 'rgba(217,119,6,0.35)' :
                approval.status === 'approved' ? 'rgba(22,163,74,0.35)' :
                approval.status === 'denied' ? 'rgba(220,38,38,0.35)' :
                'var(--border)',
            }}
          >
            <div className="approval-card-header">
              <span className="mono" style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                {approval.approval_id}
              </span>
              <span className={`risk-badge risk-${approval.risk_tier}`}>
                {approval.risk_tier.replace('_', ' ')}
              </span>
              <span className={`badge ${statusBadge(approval.status)}`} style={{ fontSize: 10 }}>
                <span className="dot" />
                {approval.status.toUpperCase()}
              </span>
              <span className="approval-time" style={{ marginLeft: 'auto' }}>
                {new Date(approval.requested_at).toLocaleString()}
              </span>
            </div>

            <div className="approval-card-body">
              <div className="approval-detail-row">
                <span className="approval-detail-label">Engagement</span>
                <span className="mono">{approval.engagement_id}</span>
              </div>
              <div className="approval-detail-row">
                <span className="approval-detail-label">Tool</span>
                <span className="mono" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{approval.tool_name}</span>
              </div>
              <div className="approval-detail-row">
                <span className="approval-detail-label">Target</span>
                <span className="mono">{approval.target}</span>
              </div>
              <div className="approval-detail-row">
                <span className="approval-detail-label">Attack Class</span>
                <span>{approval.attack_class}</span>
              </div>
              {approval.params && Object.keys(approval.params).length > 0 && (
                <details className="summary-card" style={{ marginTop: 10 }}>
                  <summary>Params ({Object.keys(approval.params).length})</summary>
                  <pre className="command-preview" style={{ border: 'none' }}>
                    {JSON.stringify(approval.params, null, 2)}
                  </pre>
                </details>
              )}
            </div>

            {approval.status === 'pending' && (
              <div className="approval-card-actions">
                <button
                  className="btn btn-success"
                  onClick={() => handleApprove(approval)}
                  disabled={actionLoading === approval.approval_id}
                >
                  <CheckIcon />
                  {actionLoading === approval.approval_id ? 'Approving…' : 'Approve'}
                </button>
                <button
                  className="btn btn-danger"
                  onClick={() => handleDeny(approval)}
                  disabled={actionLoading === approval.approval_id}
                >
                  <XIcon />
                  Deny
                </button>
              </div>
            )}

            {approval.status === 'denied' && approval.deny_reason && (
              <div style={{ padding: '10px 16px 12px', fontSize: 12, color: 'var(--text-muted)' }}>
                Reason: {approval.deny_reason}
              </div>
            )}

            {actionMsg && actionMsg.id === approval.approval_id && (
              <div style={{ padding: '0 16px 12px', fontSize: 12, color: 'var(--text-secondary)' }}>
                {actionMsg.text}
              </div>
            )}

            {jobResult && jobResult.approvalId === approval.approval_id && (
              <div style={{ padding: '0 16px 14px' }}>
                <div className="terminal">
                  <div className="terminal-header">
                    <span className="terminal-dots"><span /><span /><span /></span>
                    <span className="terminal-title mono">{jobResult.job.job_id}</span>
                    <span
                      className={`badge ${jobResult.job.status === 'completed' ? 'badge-success' : 'badge-danger'}`}
                      style={{ marginLeft: 'auto', fontSize: 10 }}
                    >
                      {jobResult.job.status?.toUpperCase()}
                    </span>
                  </div>
                  {jobResult.job.stdout && (
                    <div className="terminal-body">{jobResult.job.stdout}</div>
                  )}
                  {jobResult.job.findings && (
                    <details className="summary-card" style={{ margin: '10px 12px' }}>
                      <summary>Findings ({jobResult.job.findings.tool})</summary>
                      <pre className="command-preview" style={{ border: 'none' }}>
                        {JSON.stringify(jobResult.job.findings, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              </div>
            )}

            {actionLoading === approval.approval_id && (
              <div className="loading" style={{ padding: 12 }}>
                <span className="spinner" /> Processing…
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
