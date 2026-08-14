import { useEffect, useState } from 'react';
import { getScope, getVersions, listEngagements } from '../hooks/useApi';
import type { ScopeData, EngagementSummary, VersionInfo } from '../hooks/useApi';
import {
  TargetIcon,
  GlobeIcon,
  ShieldIcon,
  ClockIcon,
  AlertIcon,
  InfoIcon,
  EyeIcon,
} from './icons';

export function ScopeViewer() {
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string>('');
  const [scope, setScope] = useState<ScopeData | null>(null);
  const [versions, setVersions] = useState<VersionInfo[]>([]);
  const [currentVersion, setCurrentVersion] = useState<number | undefined>(undefined);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    listEngagements().then(setEngagements).catch(() => {});
  }, []);

  const loadScope = async (id: string, version?: number) => {
    setLoading(true);
    setError('');
    try {
      const [s, v] = await Promise.all([getScope(id, version), getVersions(id)]);
      setScope(s);
      setVersions(v);
      setCurrentVersion(version ?? s.version);
    } catch (e: any) {
      setError(e.message);
      setScope(null);
    } finally {
      setLoading(false);
    }
  };

  const handleSelect = (id: string) => {
    setSelectedId(id);
    setCurrentVersion(undefined);
    loadScope(id);
  };

  const handleVersionChange = (v: number) => {
    setCurrentVersion(v);
    loadScope(selectedId, v);
  };

  if (!engagements.length) {
    return (
      <div className="empty">
        <span className="empty-icon">
          <GlobeIcon />
        </span>
        <div className="empty-title">No scope files yet</div>
        <div className="empty-desc">
          Create an engagement scope to define your authorized targets, time window, and attack
          classes before running any tooling.
        </div>
      </div>
    );
  }

  const windowStatus = (() => {
    const now = Date.now();
    const s = new Date(scope!.start_time).getTime();
    const e = new Date(scope!.end_time).getTime();
    if (now < s) return { label: 'Pending', cls: 'badge-warning' };
    if (now > e) return { label: 'Expired', cls: 'badge-danger' };
    return { label: 'Active', cls: 'badge-success' };
  })();

  return (
    <div className="scope-viewer">
      <div className="section-head">
        <div>
          <h1>Scope Viewer</h1>
          <p className="section-desc">
            Inspect the immutable scope file for each engagement, including targets, exclusions,
            authorization window, and approval contacts.
          </p>
        </div>
      </div>

      <div className="toolbar">
        <label htmlFor="scope-engagement">Engagement:</label>
        <select
          id="scope-engagement"
          className="input"
          value={selectedId}
          onChange={e => handleSelect(e.target.value)}
        >
          <option value="">— Select —</option>
          {engagements.map(e => (
            <option key={e.engagement_id} value={e.engagement_id}>
              {e.engagement_name} ({e.engagement_id})
            </option>
          ))}
        </select>

        {versions.length > 1 && (
          <>
            <label htmlFor="scope-version">Version:</label>
            <select
              id="scope-version"
              className="input"
              value={currentVersion ?? ''}
              onChange={e => handleVersionChange(Number(e.target.value))}
            >
              {versions.map(v => (
                <option key={v.version} value={v.version}>
                  v{v.version}
                </option>
              ))}
            </select>
          </>
        )}
      </div>

      {loading && (
        <div className="stat-grid" aria-hidden="true">
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
        </div>
      )}
      {error && (
        <div className="error-box">
          <AlertIcon />
          <span>{error}</span>
        </div>
      )}

      {scope && !loading && (
        <div className="scope-detail">
          <div className="stat-grid">
            <div className="stat-card">
              <span className="stat-icon">
                <TargetIcon />
              </span>
              <div className="stat-body">
                <div className="stat-label">In-Scope Targets</div>
                <div className="stat-value">{scope.targets.length}</div>
                <div className="stat-detail">{scope.targets[0] ?? '—'}</div>
              </div>
            </div>
            <div className="stat-card">
              <span className="stat-icon danger">
                <ShieldIcon />
              </span>
              <div className="stat-body">
                <div className="stat-label">Excluded</div>
                <div className="stat-value">{scope.excluded_targets.length}</div>
                <div className="stat-detail">
                  {scope.excluded_targets[0] ?? 'No exclusions'}
                </div>
              </div>
            </div>
            <div className="stat-card">
              <span className="stat-icon cyan">
                <EyeIcon />
              </span>
              <div className="stat-body">
                <div className="stat-label">Attack Classes</div>
                <div className="stat-value">{scope.allowed_attack_classes.length}</div>
                <div className="stat-detail">{scope.allowed_attack_classes.join(', ')}</div>
              </div>
            </div>
            <div className="stat-card">
              <span className={`stat-icon ${windowStatus.cls === 'badge-danger' ? 'danger' : windowStatus.cls === 'badge-warning' ? 'warning' : 'success'}`}>
                <ClockIcon />
              </span>
              <div className="stat-body">
                <div className="stat-label">Window Status</div>
                <div className="stat-value" style={{ fontSize: 18, paddingTop: 4 }}>
                  <span className={`badge ${windowStatus.cls}`}>{windowStatus.label}</span>
                </div>
                <div className="stat-detail">
                  {new Date(scope.start_time).toLocaleDateString()} →{' '}
                  {new Date(scope.end_time).toLocaleDateString()}
                </div>
              </div>
            </div>
          </div>

          <div className="detail-header">
            <div>
              <span className="detail-id mono">{scope.engagement_id}</span>
              <span className="detail-version mono">v{scope.version}</span>
            </div>
            <div className="detail-name">{scope.engagement_name}</div>
          </div>

          <div className="detail-grid">
            <div className="detail-card">
              <div className="detail-card-title">Time Window</div>
              <div className="detail-card-body">
                <div className="detail-row">
                  <span className="detail-label">Start</span>
                  <span className="mono">{new Date(scope.start_time).toLocaleString()}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">End</span>
                  <span className="mono">{new Date(scope.end_time).toLocaleString()}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Status</span>
                  <span className={`badge ${windowStatus.cls}`}>{windowStatus.label}</span>
                </div>
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-card-title">Targets</div>
              <div className="detail-card-body">
                {scope.targets.map((t, i) => (
                  <span key={i} className="detail-chip mono">{t}</span>
                ))}
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-card-title">Excluded</div>
              <div className="detail-card-body">
                {scope.excluded_targets.length === 0 ? (
                  <span className="text-muted">None</span>
                ) : (
                  scope.excluded_targets.map((t, i) => (
                    <span key={i} className="detail-chip mono chip-red">{t}</span>
                  ))
                )}
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-card-title">Allowed Attack Classes</div>
              <div className="detail-card-body">
                <div className="tag-list">
                  {scope.allowed_attack_classes.map(ac => (
                    <span key={ac} className="tag">{ac}</span>
                  ))}
                </div>
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-card-title">Authorization Contact</div>
              <div className="detail-card-body">
                <div className="detail-row">
                  <span className="detail-label">Name</span>
                  <span>{scope.authorization_contact.name}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Email</span>
                  <span>{scope.authorization_contact.email}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Role</span>
                  <span>{scope.authorization_contact.role}</span>
                </div>
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-card-title">Settings</div>
              <div className="detail-card-body">
                <div className="detail-row">
                  <span className="detail-label">Emergency Contact</span>
                  <span className="mono">{scope.emergency_contact}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Rate Limit</span>
                  <span className="mono">{scope.rate_limit ? `${scope.rate_limit} req/s` : 'None'}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Notify Before Exploit</span>
                  <span>{scope.notify_before_exploit ? 'Yes' : 'No'}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="alert alert-info" style={{ marginTop: 20 }}>
            <InfoIcon />
            <span>
              Scope files are <strong>immutable</strong>. To change targets, exclusions, or the
              authorization window, edit the engagement in the New Scope tab — this creates a new
              version rather than overwriting the existing one.
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
