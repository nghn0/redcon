import { useState, useEffect, useCallback } from 'react';
import { listEngagements, validateAction } from '../hooks/useApi';
import type { EngagementSummary, ValidationResult } from '../hooks/useApi';
import { StatusBadge } from './StatusBadge';
import { AlertIcon, CheckCircleIcon, ClockIcon, ListIcon, TargetIcon } from './icons';

const ATTACK_CLASSES = [
  'recon', 'web', 'network', 'exploitation', 'social_eng', 'mitm',
];

function toLocalDatetime(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function nowLocal(): string {
  return toLocalDatetime(new Date());
}

export function ValidatePanel() {
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [engagementId, setEngagementId] = useState('');
  const [target, setTarget] = useState('');
  const [attackClass, setAttackClass] = useState('recon');
  const [timestamp, setTimestamp] = useState(nowLocal);
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<{ action: any; result: ValidationResult }[]>([]);
  const [stale, setStale] = useState(false);

  useEffect(() => {
    listEngagements().then(setEngagements).catch(() => {});
  }, []);

  const handleValidate = useCallback(async () => {
    if (!engagementId || !target) return;
    setLoading(true);
    setError('');
    setStale(false);
    try {
      const res = await validateAction({
        engagement_id: engagementId,
        target: target.trim(),
        attack_class: attackClass,
        timestamp: new Date(timestamp).toISOString(),
      });
      setResult(res);
      setHistory(prev => [{ action: { target, attack_class: attackClass, timestamp }, result: res }, ...prev].slice(0, 20));
    } catch (e: any) {
      setError(e.message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, [engagementId, target, attackClass, timestamp]);

  const handleInputChange = (setter: (v: any) => void, value: any) => {
    setter(value);
    if (result) setStale(true);
  };

  const preset = (target: string, attackClass: string, timestampOffset?: number) => {
    setTarget(target);
    setAttackClass(attackClass);
    if (timestampOffset !== undefined) {
      const d = new Date(Date.now() + timestampOffset);
      setTimestamp(toLocalDatetime(d));
    } else {
      setTimestamp(nowLocal());
    }
    if (result) setStale(true);
  };

  return (
    <div className="validate-panel">
      <div className="validate-form">
        <div className="section-head">
          <div>
            <h1>Validate Action</h1>
            <p className="section-desc">
              Test whether a proposed action passes the scope boundary — exclusion list, target
              scope, authorization window, and allowed attack classes.
            </p>
          </div>
        </div>

        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-header">
            <span className="card-title">Action Request</span>
          </div>
          <div className="card-body">
            <div className="form-row">
              <div className="form-group flex-1">
                <label htmlFor="val-engagement">Engagement</label>
                <select
                  id="val-engagement"
                  className="input"
                  value={engagementId}
                  onChange={e => handleInputChange(setEngagementId, e.target.value)}
                >
                  <option value="">— Select —</option>
                  {engagements.map(e => (
                    <option key={e.engagement_id} value={e.engagement_id}>
                      {e.engagement_name} ({e.engagement_id})
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-group flex-1">
                <label htmlFor="val-target">
                  Target <span className="label-hint">(IP, CIDR, or domain)</span>
                </label>
                <input
                  id="val-target"
                  type="text"
                  className="input mono"
                  value={target}
                  onChange={e => handleInputChange(setTarget, e.target.value)}
                  placeholder="e.g. 203.0.113.10"
                />
              </div>
            </div>
            <div className="form-row" style={{ marginTop: 16 }}>
              <div className="form-group">
                <label htmlFor="val-class">Attack Class</label>
                <select
                  id="val-class"
                  className="input"
                  value={attackClass}
                  onChange={e => handleInputChange(setAttackClass, e.target.value)}
                >
                  {ATTACK_CLASSES.map(ac => (
                    <option key={ac} value={ac}>{ac}</option>
                  ))}
                </select>
              </div>
              <div className="form-group flex-1">
                <label htmlFor="val-time">Timestamp</label>
                <div className="input-with-button">
                  <input
                    id="val-time"
                    type="datetime-local"
                    className="input"
                    value={timestamp}
                    onChange={e => handleInputChange(setTimestamp, e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn-now"
                    onClick={() => {
                      setTimestamp(nowLocal());
                      if (result) setStale(true);
                    }}
                    title="Reset to current time"
                  >
                    Now
                  </button>
                </div>
              </div>
            </div>
            <button
              className="btn btn-primary"
              style={{ marginTop: 16 }}
              onClick={handleValidate}
              disabled={loading || !engagementId || !target}
            >
              {loading ? (
                <>
                  <span className="spinner" />
                  Validating…
                </>
              ) : (
                <>
                  <CheckCircleIcon />
                  Validate Action
                </>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="server-error" style={{ marginTop: 12 }}>
            <AlertIcon />
            <span>{error}</span>
          </div>
        )}

        {result && !stale && (
          <div
            className="result-box"
            style={{
              borderColor: result.allowed ? 'rgba(22,163,74,0.35)' : 'rgba(220,38,38,0.35)',
              background: result.allowed ? 'rgba(22,163,74,0.05)' : 'rgba(220,38,38,0.05)',
            }}
          >
            <div className="result-header">
              <StatusBadge allowed={result.allowed} />
              <span className="mono result-target">{target}</span>
            </div>
            <div className="result-reason mono">{result.reason}</div>
          </div>
        )}

        {result && stale && (
          <div className="result-box result-stale">
            <div className="result-header">
              <span className="stale-badge">STALE</span>
              <span className="mono result-target">{target}</span>
            </div>
            <div className="result-reason" style={{ color: 'var(--text-muted)' }}>
              Inputs changed — re-run validation to see updated result
            </div>
          </div>
        )}

        <div className="form-section" style={{ marginTop: 24 }}>
          <div className="form-section-title">Quick Test Presets</div>
          <div className="preset-grid">
            <button className="preset-btn" onClick={() => preset('203.0.113.10', 'recon')}>
              In-scope IP
            </button>
            <button className="preset-btn" onClick={() => preset('10.0.0.1', 'recon')}>
              Out-of-scope IP
            </button>
            <button className="preset-btn" onClick={() => preset('203.0.113.50', 'recon')}>
              Excluded IP
            </button>
            <button className="preset-btn" onClick={() => preset('203.0.113.10', 'exploitation')}>
              Disallowed class
            </button>
            <button className="preset-btn" onClick={() => preset('203.0.113.10', 'recon', -365 * 86400000)}>
              Outside time window
            </button>
            <button className="preset-btn" onClick={() => preset('example.com', 'web')}>
              In-scope domain
            </button>
            <button className="preset-btn" onClick={() => preset('admin.example.com', 'web')}>
              Excluded domain
            </button>
          </div>
        </div>
      </div>

      {history.length > 0 && (
        <div className="history-section">
          <div className="form-section-title">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <ListIcon style={{ width: 13, height: 13, color: 'var(--text-muted)' }} />
              History
            </span>
          </div>
          <div className="history-list">
            {history.map((h, i) => (
              <div
                key={i}
                className="history-item"
                style={{
                  borderLeft: `3px solid ${h.result.allowed ? 'var(--accent-success)' : 'var(--accent-danger)'}`,
                }}
              >
                <StatusBadge allowed={h.result.allowed} />
                <span className="mono" style={{ flex: 1, color: 'var(--text-secondary)' }}>
                  {h.action.target}
                </span>
                <span className="mono" style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                  {h.action.attack_class}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {history.length === 0 && (
        <div className="history-section">
          <div className="form-section-title">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <ClockIcon style={{ width: 13, height: 13, color: 'var(--text-muted)' }} />
              History
            </span>
          </div>
          <div className="empty-state" style={{ padding: '24px 12px' }}>
            <TargetIcon style={{ width: 22, height: 22, marginBottom: 8, color: 'var(--text-muted)' }} />
            <div>Run a validation to see your check history</div>
          </div>
        </div>
      )}
    </div>
  );
}
