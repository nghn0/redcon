import { useState, useEffect, type JSX } from 'react';
import {
  listTools,
  buildToolCommand,
  installTool,
  deleteTool,
  runTool,
  getRunResult,
  type ToolInfo,
} from '../hooks/useApi';
import {
  TargetIcon,
  GlobeIcon,
  ActivityIcon,
  WrenchIcon,
  EyeIcon,
  FileIcon,
  KeyIcon,
  AlertIcon,
  DownloadIcon,
  TrashIcon,
  PlayIcon,
  CheckCircleIcon,
} from './icons';

const SAFE_TARGETS_NMAP = ['127.0.0.1', 'localhost', 'scanme.nmap.org'];
const SAFE_TARGETS_DEFAULT = ['127.0.0.1', 'localhost'];

const TOOL_ICONS: Record<string, (props: any) => JSX.Element> = {
  nmap: TargetIcon,
  subfinder: GlobeIcon,
  nuclei: ActivityIcon,
  gobuster: WrenchIcon,
  nikto: EyeIcon,
  sqlmap: FileIcon,
  hydra: KeyIcon,
};

function getSafeTargets(toolName: string): string[] {
  return toolName === 'nmap' ? SAFE_TARGETS_NMAP : SAFE_TARGETS_DEFAULT;
}

function RiskBadge({ tier }: { tier: string }) {
  const cls =
    tier === 'passive' ? 'badge-success' :
    tier === 'active_scan' ? 'badge-warning' :
    'badge-danger';
  return (
    <span className={`badge ${cls}`} style={{ fontSize: 10, padding: '2px 9px' }}>
      <span className="dot" />
      {tier.replace('_', ' ')}
    </span>
  );
}

export function ToolRegistry() {
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [selectedTool, setSelectedTool] = useState('');
  const [paramValues, setParamValues] = useState<Record<string, string>>({});
  const [builtCommand, setBuiltCommand] = useState<string[] | null>(null);
  const [buildError, setBuildError] = useState('');

  const [installing, setInstalling] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [installOutput, setInstallOutput] = useState<string | null>(null);

  const [runToolName, setRunToolName] = useState('');
  const [runTarget, setRunTarget] = useState('127.0.0.1');
  const [runLoading, setRunLoading] = useState(false);
  const [runStatus, setRunStatus] = useState<string | null>(null);
  const [runStdout, setRunStdout] = useState('');
  const [runStderr, setRunStderr] = useState('');
  const [runParsed, setRunParsed] = useState<any>(null);
  const [runError, setRunError] = useState('');

  useEffect(() => {
    fetchTools();
  }, []);

  async function fetchTools() {
    setLoading(true);
    setError('');
    try {
      const data = await listTools();
      setTools(data);
    } catch (e: any) {
      setError(e.message || 'Failed to load tools');
    } finally {
      setLoading(false);
    }
  }

  function handleSelectTool(name: string) {
    setSelectedTool(name);
    setParamValues({});
    setBuiltCommand(null);
    setBuildError('');
    setInstallOutput(null);
    setRunToolName(name);
    setRunTarget(getSafeTargets(name)[0]);
    setRunStatus(null);
    setRunStdout('');
    setRunStderr('');
    setRunParsed(null);
    setRunError('');
  }

  function handleParamChange(key: string, value: string) {
    setParamValues(prev => ({ ...prev, [key]: value }));
  }

  async function handleBuildCommand() {
    if (!selectedTool) return;
    setBuiltCommand(null);
    setBuildError('');
    try {
      const result = await buildToolCommand(selectedTool, paramValues);
      setBuiltCommand(result.command);
    } catch (e: any) {
      setBuildError(e.message || 'Build failed');
    }
  }

  async function handleInstall(name: string) {
    setInstalling(name);
    setInstallOutput(null);
    try {
      const result = await installTool(name);
      setInstallOutput(result.output);
      await fetchTools();
    } catch (e: any) {
      setInstallOutput(e.message || 'Install failed');
    } finally {
      setInstalling(null);
    }
  }

  async function handleDelete(name: string) {
    setDeleting(name);
    setInstallOutput(null);
    try {
      const result = await deleteTool(name);
      setInstallOutput(result.output);
      await fetchTools();
    } catch (e: any) {
      setInstallOutput(e.message || 'Delete failed');
    } finally {
      setDeleting(null);
    }
  }

  async function handleRun() {
    if (!runToolName) return;
    setRunLoading(true);
    setRunStatus(null);
    setRunStdout('');
    setRunStderr('');
    setRunParsed(null);
    setRunError('');
    try {
      const params: Record<string, string> = { target: runTarget };
      const { job_id } = await runTool(runToolName, params);
      pollJob(job_id);
    } catch (e: any) {
      setRunError(e.message || 'Run failed');
      setRunLoading(false);
    }
  }

  function pollJob(jobId: string) {
    const interval = setInterval(async () => {
      try {
        const result = await getRunResult(jobId);
        if (result.status === 'completed' || result.status === 'error' || result.status === 'timeout') {
          clearInterval(interval);
          setRunLoading(false);
          setRunStatus(result.status);
          setRunStdout(result.stdout || '');
          setRunStderr(result.stderr || '');
          if (result.findings) {
            setRunParsed(result.findings);
          }
        }
      } catch {
        clearInterval(interval);
        setRunLoading(false);
      }
    }, 1000);
  }

  const selected = tools.find(t => t.name === selectedTool);

  if (loading) return <div className="loading">Loading tools…</div>;
  if (error) return (
    <div className="error-box">
      <AlertIcon />
      <span>{error}</span>
    </div>
  );

  return (
    <div className="tool-registry">
      <div className="section-head">
        <div>
          <h1>Tool Registry</h1>
          <p className="section-desc">
            A fixed menu of vetted tools. Commands are built from strict templates with
            whitelist-validated parameters — never free-form shell input.
          </p>
        </div>
      </div>

      <div className="tool-grid">
        {tools.map(tool => {
          const Icon = TOOL_ICONS[tool.name] || WrenchIcon;
          return (
            <div
              key={tool.name}
              className={`tool-card ${selectedTool === tool.name ? 'selected' : ''}`}
              onClick={() => handleSelectTool(tool.name)}
              role="button"
              tabIndex={0}
              onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  handleSelectTool(tool.name);
                }
              }}
            >
              <div className="tool-card-header">
                <span className="tool-card-icon">
                  <Icon />
                </span>
                <span className="tool-card-name">{tool.name}</span>
                <span style={{ marginLeft: 'auto' }}>
                  <RiskBadge tier={tool.risk_tier} />
                </span>
              </div>
              <div className="tool-card-desc">{tool.description}</div>
              <div className="tool-card-status">
                {tool.installed ? (
                  <span className="badge badge-success" style={{ fontSize: 10 }}>
                    <span className="dot" />
                    Installed
                  </span>
                ) : (
                  <span className="badge badge-warning" style={{ fontSize: 10 }}>
                    <span className="dot" />
                    Not installed
                  </span>
                )}
              </div>
              <div className="tool-card-actions">
                {!tool.installed ? (
                  <button
                    className="btn btn-secondary btn-sm"
                    disabled={installing === tool.name}
                    onClick={e => {
                      e.stopPropagation();
                      handleInstall(tool.name);
                    }}
                  >
                    <DownloadIcon />
                    {installing === tool.name ? 'Installing…' : 'Download'}
                  </button>
                ) : (
                  <button
                    className="btn btn-danger btn-sm"
                    disabled={deleting === tool.name}
                    onClick={e => {
                      e.stopPropagation();
                      handleDelete(tool.name);
                    }}
                  >
                    <TrashIcon />
                    {deleting === tool.name ? 'Deleting…' : 'Delete'}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {installOutput && (
        <details className="install-output">
          <summary>Install / Delete Output</summary>
          <pre>{installOutput}</pre>
        </details>
      )}

      {selected && (
        <div className="build-panel">
          <div className="form-section-title">
            Configure — {selected.name}
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
                  className="input"
                  placeholder={key}
                  value={paramValues[key] || ''}
                  onChange={e => handleParamChange(key, e.target.value)}
                />
              </div>
            ))}
          </div>

          {buildError && (
            <div className="error-box" style={{ marginTop: 12 }}>
              <AlertIcon />
              <span>{buildError}</span>
            </div>
          )}

          {builtCommand && (
            <div className="terminal" style={{ marginTop: 14 }}>
              <div className="terminal-header">
                <span className="terminal-dots"><span /><span /><span /></span>
                <span className="terminal-title">resolved command</span>
              </div>
              <div className="terminal-body ok">{builtCommand.join(' ')}</div>
            </div>
          )}

          <button className="btn btn-primary" onClick={handleBuildCommand} style={{ marginTop: 14 }}>
            <CheckCircleIcon />
            Build Command
          </button>

          {selected.installed && (
            <div className="run-section">
              <div className="form-section-title">Run {selected.name}</div>
              <div className="form-row">
                <div className="form-group flex-1">
                  <label htmlFor={`run-target-${selected.name}`}>Target (safe targets only)</label>
                  <select
                    id={`run-target-${selected.name}`}
                    className="input"
                    value={runTarget}
                    onChange={e => setRunTarget(e.target.value)}
                  >
                    {getSafeTargets(selected.name).map(t => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
              </div>
              {runError && (
                <div className="error-box" style={{ marginTop: 12 }}>
                  <AlertIcon />
                  <span>{runError}</span>
                </div>
              )}
              {runLoading && (
                <div className="loading" style={{ padding: 16 }}>
                  <span className="spinner" /> Running {selected.name}…
                </div>
              )}
              {runStatus && (
                <div className="terminal" style={{ marginTop: 12 }}>
                  <div className="terminal-header">
                    <span className="terminal-dots"><span /><span /><span /></span>
                    <span className="terminal-title">
                      {runStatus === 'completed' ? 'completed' : runStatus} · exit
                    </span>
                  </div>
                  <div className={`terminal-body ${runStatus === 'completed' ? 'ok' : 'err'}`}>
                    {runStdout}
                    {runStderr && `\n${runStderr}`}
                  </div>
                </div>
              )}
              {runParsed && (
                <div style={{ marginTop: 12 }}>
                  <div className="section-label" style={{ marginBottom: 8 }}>Parsed Findings</div>
                  <pre className="command-preview">{JSON.stringify(runParsed, null, 2)}</pre>
                </div>
              )}
              <button
                className="btn btn-primary"
                onClick={handleRun}
                disabled={runLoading}
                style={{ marginTop: 12 }}
              >
                <PlayIcon />
                {runLoading ? 'Running…' : 'Run'}
              </button>
            </div>
          )}
        </div>
      )}

      {!selected && (
        <div className="empty" style={{ marginTop: 24 }}>
          <span className="empty-icon">
            <WrenchIcon />
          </span>
          <div className="empty-title">Select a tool to configure</div>
          <div className="empty-desc">
            Choose a tool card above to build a validated command or run it against a safe test
            target.
          </div>
        </div>
      )}
    </div>
  );
}
