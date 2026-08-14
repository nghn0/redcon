import { useState, useEffect, useRef } from 'react';
import {
  listEngagements,
  listTools,
  listOrchestratorSessions,
  createOrchestratorSession,
  sendOrchestratorMessage,
  getOrchestratorSession,
  checkOrchestratorLLM,
  confirmOrchestratorParams,
  cancelOrchestratorParams,
  buildToolCommand,
  type EngagementSummary,
  type OrchestratorState,
  type OrchestratorSession,
  type ToolInfo,
} from '../hooks/useApi';
import {
  BrainIcon,
  PlugIcon,
  SendIcon,
  ActivityIcon,
  InfoIcon,
  ClockIcon,
  TerminalIcon,
} from './icons';

type MessageEntry = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  action?: {
    tool_name: string;
    params: Record<string, string>;
    outcome: string;
    target?: string;
    job_id?: string;
    approval_id?: string;
    reason?: string;
  };
  findings?: Array<{ type: string; detail: Record<string, unknown>; _tool?: string }>;
};

function outcomeBadge(outcome: string) {
  switch (outcome) {
    case 'executing':
    case 'approved':
      return { cls: 'badge-blue', label: outcome === 'executing' ? 'RUNNING' : 'APPROVED' };
    case 'completed':
      return { cls: 'badge-success', label: 'COMPLETED' };
    case 'pending_approval':
      return { cls: 'badge-warning', label: 'PENDING' };
    case 'denied':
      return { cls: 'badge-danger', label: 'DENIED' };
    case 'timeout':
      return { cls: 'badge-danger', label: 'TIMEOUT' };
    case 'error':
      return { cls: 'badge-danger', label: 'ERROR' };
    default:
      return { cls: 'badge-neutral', label: (outcome || 'UNKNOWN').toUpperCase() };
  }
}

function outcomeText(a: { outcome?: string; reason?: string }) {
  switch (a.outcome) {
    case 'completed':
      return '✓ Completed';
    case 'approved':
      return '✓ Approved & ran';
    case 'pending_approval':
      return '⚠ Awaiting approval';
    case 'denied':
      return `✗ Denied${a.reason ? ': ' + a.reason : ''}`;
    case 'executing':
      return 'Executing...';
    case 'error':
      return '✗ Error';
    case 'timeout':
      return '✗ Timeout';
    default:
      return a.outcome || '';
  }
}

export function OrchestratorPanel() {
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [sessions, setSessions] = useState<OrchestratorSession[]>([]);
  const [selectedEngagement, setSelectedEngagement] = useState('');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<MessageEntry[]>([]);
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [llmConnected, setLlmConnected] = useState(false);
  const [llmConnecting, setLlmConnecting] = useState(false);
  const [llmError, setLlmError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const statePollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const userMessagesRef = useRef<MessageEntry[]>([]);

  // Parked param confirmation: the editable params the user is reviewing
  // before a proposed tool runs. Kept in local state so edits survive the
  // 2s state-poll rebuilds (guarded by pendingDirtyRef). A parked confirm can
  // also be an auto-install proposal (action_kind === 'install'), in which case
  // there are no editable params — the card shows the install/verify commands.
  const [pendingParams, setPendingParams] = useState<{
    tool_name: string;
    params: Record<string, string>;
    action_kind?: 'install' | 'execute';
    capability?: string;
    install_command?: string;
    verification_command?: string;
    requirements?: string[];
  } | null>(null);
  const pendingDirtyRef = useRef(false);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [preview, setPreview] = useState<{ command: string[] | null; error: string }>({
    command: null,
    error: '',
  });

  useEffect(() => {
    listEngagements().then(setEngagements).catch(() => {});
    listOrchestratorSessions().then(setSessions).catch(() => {});
    listTools().then(setTools).catch(() => {});
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    return () => stopStatePolling();
  }, []);

  // The backend auto-drives the workflow (worker continues after each tool or
  // after a pending approval is granted). Poll session state so live progress —
  // new actions, findings, chat replies, and the completed summary — shows up
  // automatically without further user input.
  function startStatePolling() {
    stopStatePolling();
    if (!sessionId) return;

    statePollRef.current = setInterval(async () => {
      try {
        const state = await getOrchestratorSession(sessionId);
        setMessages(rebuildMessagesFromState(state));
        syncPendingParams(state);
        if (state.status === 'completed') {
          stopStatePolling();
          setLoading(false);
        }
      } catch {
        // poll will retry
      }
    }, 2000);
  }

  function stopStatePolling() {
    if (statePollRef.current) {
      clearInterval(statePollRef.current);
      statePollRef.current = null;
    }
  }

  function syncPendingParams(state: OrchestratorState) {
    const pc = state.pending_param_confirm;
    if (!pc) {
      setPendingParams(null);
      pendingDirtyRef.current = false;
      return;
    }
    setPendingParams(prev => {
      const sameProposal =
        prev && prev.tool_name === pc.tool_name && prev.action_kind === pc.action_kind;
      if (sameProposal && pendingDirtyRef.current) {
        return prev;
      }
      pendingDirtyRef.current = false;
      return {
        tool_name: pc.tool_name,
        params: { ...(pc.params || {}) },
        action_kind: pc.action_kind || 'execute',
        capability: pc.capability,
        install_command: pc.install_command,
        verification_command: pc.verification_command,
        requirements: pc.requirements,
      };
    });
  }

  function refreshPreview(toolName: string, params: Record<string, string>) {
    buildToolCommand(toolName, params)
      .then(built => setPreview({ command: built.command, error: '' }))
      .catch((e: any) => setPreview({ command: null, error: e.message || 'Invalid parameters' }));
  }

  function addMessage(msg: MessageEntry) {
    setMessages(prev => [...prev, msg]);
  }

  function addSystemMessage(text: string, findings?: any) {
    addMessage({
      id: `sys-${Date.now()}`,
      role: 'assistant',
      content: text,
      timestamp: new Date().toISOString(),
      findings: findings?.findings,
    });
  }

  function handleStateUpdate(state: OrchestratorState) {
    if (!state.session_id) return;

    setMessages(rebuildMessagesFromState(state));
    syncPendingParams(state);
    setLoading(false);

    if (state.status === 'completed') {
      stopStatePolling();
    } else {
      startStatePolling();
    }
  }

  async function handleStartSession() {
    if (!selectedEngagement) return;
    setSessionLoading(true);
    setMessages([]);
    stopStatePolling();
    userMessagesRef.current = [];
    setSessionId(null);
    setPendingParams(null);
    pendingDirtyRef.current = false;
    try {
      const state = await createOrchestratorSession(selectedEngagement, inputText || 'Explore the target');
      setSessionId(state.session_id || null);
      listOrchestratorSessions().then(setSessions).catch(() => {});
      handleStateUpdate(state);
      setInputText('');
    } catch (e: any) {
      addSystemMessage(`Error: ${e.message}`);
    } finally {
      setSessionLoading(false);
    }
  }

  async function handleSendMessage() {
    if (!sessionId || !inputText.trim() || loading) return;
    setLoading(true);
    const userText = inputText;
    setInputText('');

    const userMsg: MessageEntry = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: userText,
      timestamp: new Date().toISOString(),
    };
    userMessagesRef.current = [...userMessagesRef.current, userMsg];
    addMessage(userMsg);

    try {
      const state = await sendOrchestratorMessage(sessionId, userText);
      handleStateUpdate(state);
    } catch (e: any) {
      addSystemMessage(`Error: ${e.message}`);
      setLoading(false);
    }
  }

  function rebuildMessagesFromState(state: OrchestratorState): MessageEntry[] {
    const historyMsgs: MessageEntry[] = (state.action_history || []).map(item => {
      if (item.type === 'user') {
        return {
          id: `user-${item.timestamp}`,
          role: 'user',
          content: item.content || '',
          timestamp: item.timestamp,
        };
      }
      if (item.type === 'chat') {
        return {
          id: `chat-${item.timestamp}`,
          role: 'assistant',
          content: item.content || '',
          timestamp: item.timestamp,
        };
      }
      if (item.type === 'summary') {
        return {
          id: `summary-${item.timestamp}`,
          role: 'assistant',
          content: item.content || 'Engagement complete.',
          timestamp: item.timestamp,
        };
      }
      if (item.type === 'action') {
        const toolName = item.tool_name || 'unknown';
        const findings = (state.findings_so_far || []).filter(f => f._tool === toolName);
        return {
          id: `action-${item.timestamp}`,
          role: 'assistant',
          content: `**${toolName}** → ${item.target || 'unknown'}\n${outcomeText(item)}`,
          timestamp: item.timestamp,
          action: {
            tool_name: toolName,
            params: item.params || {},
            outcome: item.outcome || 'completed',
            target: item.target,
            job_id: item.job_id,
            approval_id: item.approval_id,
            reason: item.reason,
          },
          findings: findings.length > 0 ? findings : undefined,
        };
      }
      return null;
    }).filter(Boolean) as MessageEntry[];

    const goalMsg: MessageEntry[] = state.goal
      ? [{ id: 'user-goal', role: 'user', content: state.goal, timestamp: state.created_at || state.updated_at }]
      : [];

    // User messages are now persisted in action_history. Keep the optimistic
    // ref entries only when the server hasn't stored them yet (e.g. a send that
    // failed or is still in flight) to avoid duplicates.
    const historyUserContents = new Set(
      (state.action_history || []).filter(i => i.type === 'user').map(i => i.content),
    );
    const pendingUserMsgs = userMessagesRef.current.filter(
      m => !historyUserContents.has(m.content),
    );

    const all = [...goalMsg, ...pendingUserMsgs, ...historyMsgs].sort((a, b) =>
      (a.timestamp || '').localeCompare(b.timestamp || ''),
    );

    if (state.status === 'completed' && state.summary) {
      all.push({
        id: 'summary-end',
        role: 'assistant',
        content: `✅ ${state.summary}`,
        timestamp: state.updated_at,
      });
    }

    return all;
  }

  async function handleConnectLLM() {
    setLlmConnecting(true);
    setLlmError(null);
    try {
      const result = await checkOrchestratorLLM();
      if (result.connected) {
        setLlmConnected(true);
      } else {
        setLlmError(result.error || 'Failed to connect');
      }
    } catch (e: any) {
      setLlmError(e.message);
    } finally {
      setLlmConnecting(false);
    }
  }

  async function handleResumeSession(sessionIdToResume: string) {
    setSessionLoading(true);
    setMessages([]);
    stopStatePolling();
    userMessagesRef.current = [];
    try {
      const state = await getOrchestratorSession(sessionIdToResume);
      setSessionId(state.session_id || null);
      setSelectedEngagement(state.engagement_id);
      setMessages(rebuildMessagesFromState(state));
      syncPendingParams(state);
      if (state.status === 'completed') {
        stopStatePolling();
      } else {
        startStatePolling();
      }
    } catch (e: any) {
      addSystemMessage(`Error loading session: ${e.message}`);
    } finally {
      setSessionLoading(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (!sessionId) {
        handleStartSession();
      } else {
        handleSendMessage();
      }
    }
  }

  async function handleConfirmParamsExecute() {
    if (!sessionId || !pendingParams || confirmBusy) return;
    setConfirmBusy(true);
    pendingDirtyRef.current = false;
    try {
      const state = await confirmOrchestratorParams(sessionId, pendingParams.params);
      handleStateUpdate(state);
    } catch (e: any) {
      addSystemMessage(`Error confirming params: ${e.message}`);
      setLoading(false);
    } finally {
      setConfirmBusy(false);
    }
  }

  async function handleCancelParams() {
    if (!sessionId || !pendingParams || confirmBusy) return;
    setConfirmBusy(true);
    pendingDirtyRef.current = false;
    try {
      const state = await cancelOrchestratorParams(sessionId);
      handleStateUpdate(state);
    } catch (e: any) {
      addSystemMessage(`Error cancelling action: ${e.message}`);
      setLoading(false);
    } finally {
      setConfirmBusy(false);
    }
  }

  function handlePendingParamChange(key: string, value: string) {
    pendingDirtyRef.current = true;
    setPendingParams(prev => {
      if (!prev) return prev;
      return { ...prev, params: { ...prev.params, [key]: value } };
    });
  }

  useEffect(() => {
    if (pendingParams) {
      if (pendingParams.action_kind === 'install') {
        setPreview({ command: null, error: '' });
      } else {
        refreshPreview(pendingParams.tool_name, pendingParams.params);
      }
    } else {
      setPreview({ command: null, error: '' });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingParams]);

  const isNewSession = !sessionId;
  const resumeSessions = sessions.filter(s => s.status === 'active' || s.status === 'pending_approval');

  return (
    <div className="orchestrator-panel">
      <div className="section-head">
        <div>
          <h1>AI Security Orchestrator</h1>
          <p className="section-desc">
            The LLM proposes scope-validated tool actions through the existing pipeline. Passive
            tools auto-execute; active-scan and exploit tools route through the Approval Gate.
          </p>
        </div>
      </div>

      {isNewSession && resumeSessions.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <span className="card-title">
              <ClockIcon />
              Resume Session
            </span>
          </div>
          <div className="card-body" style={{ padding: '12px 16px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {resumeSessions.slice(0, 5).map(s => (
                <button
                  key={s.session_id}
                  className="btn btn-secondary"
                  style={{ textAlign: 'left', justifyContent: 'flex-start', padding: '9px 12px' }}
                  onClick={() => handleResumeSession(s.session_id)}
                  disabled={sessionLoading}
                >
                  <span className="mono" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{s.session_id}</span>
                  <span style={{ color: 'var(--text-muted)' }}>—</span>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.engagement_id} ({s.goal.slice(0, 60)})
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {isNewSession && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <span className="card-title">
              <BrainIcon />
              Session Setup
            </span>
          </div>
          <div className="card-body">
            <div className="form-row">
              <div className="form-group flex-1">
                <label>LLM Connection</label>
                {!llmConnected ? (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                    <button className="btn btn-primary" onClick={handleConnectLLM} disabled={llmConnecting}>
                      {llmConnecting ? (
                        <>
                          <span className="spinner" />
                          Connecting…
                        </>
                      ) : (
                        <>
                          <PlugIcon />
                          Connect to LLM
                        </>
                      )}
                    </button>
                    {llmError && (
                      <span style={{ color: 'var(--accent-danger)', fontSize: 12 }}>{llmError}</span>
                    )}
                  </div>
                ) : (
                  <span className="badge badge-success">
                    <span className="dot" />
                    LLM Connected
                  </span>
                )}
              </div>
            </div>

            <div className="form-row" style={{ marginTop: 14, opacity: llmConnected ? 1 : 0.4, pointerEvents: llmConnected ? 'auto' : 'none' }}>
              <div className="form-group flex-1">
                <label htmlFor="orch-engagement">Engagement</label>
                <select
                  id="orch-engagement"
                  className="input"
                  value={selectedEngagement}
                  onChange={e => setSelectedEngagement(e.target.value)}
                >
                  <option value="">-- Select engagement --</option>
                  {engagements.map(e => (
                    <option key={e.engagement_id} value={e.engagement_id}>
                      {e.engagement_name} ({e.engagement_id})
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="orchestrator-chat">
        <div className="chat-messages">
          {messages.length === 0 && (
            <div className="empty" style={{ border: 'none', background: 'transparent' }}>
              <span className="empty-icon">
                <BrainIcon />
              </span>
              <div className="empty-title">
                {isNewSession
                  ? !llmConnected
                    ? 'Connect the LLM to begin'
                    : 'Ready to plan an engagement'
                  : 'Session created'}
              </div>
              <div className="empty-desc">
                {isNewSession
                  ? !llmConnected
                    ? 'Click "Connect to LLM" above to enable the AI Assistant.'
                    : 'Select an engagement, type a goal, and press Enter to start.'
                  : 'Type a message to continue the engagement.'}
              </div>
            </div>
          )}
          {messages.map(msg => {
            const badge = msg.action ? outcomeBadge(msg.action.outcome) : null;
            return (
              <div key={msg.id} className={`chat-message chat-${msg.role}`}>
                <div className="chat-avatar">
                  {msg.role === 'user' ? 'U' : 'AI'}
                </div>
                <div className="chat-bubble">
                  {msg.action ? (
                    <div className="chat-action-card">
                      <div className="chat-action-header">
                        <TerminalIcon style={{ width: 14, height: 14, color: 'var(--text-muted)' }} />
                        <span className="mono" style={{ color: 'var(--text-primary)', fontWeight: 700, fontSize: 14 }}>
                          {msg.action.tool_name}
                        </span>
                        {badge && (
                          <span className={`badge ${badge.cls}`} style={{ fontSize: 10 }}>
                            {badge.label}
                          </span>
                        )}
                      </div>
                      <div className="chat-action-detail">
                        <span className="chat-detail-label">Target:</span>
                        <span className="mono">{msg.action.target || 'unknown'}</span>
                      </div>
                      {msg.action.params && Object.keys(msg.action.params).length > 0 && (
                        <details className="summary-card" style={{ marginTop: 8 }}>
                          <summary>Params ({Object.keys(msg.action.params).length})</summary>
                          <pre className="chat-params" style={{ border: 'none' }}>
                            {JSON.stringify(msg.action.params, null, 2)}
                          </pre>
                        </details>
                      )}
                      {msg.action.outcome === 'denied' && msg.action.reason && (
                        <div className="chat-deny-reason">{msg.action.reason}</div>
                      )}
                      {msg.action.outcome === 'pending_approval' && (
                        <div className="chat-pending-hint">
                          Awaiting human approval — go to the <strong>Approvals</strong> tab to approve or deny
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="chat-text">{msg.content}</div>
                  )}
                  {msg.findings && msg.findings.length > 0 && (
                    <details className="summary-card" style={{ marginTop: 8 }}>
                      <summary>Findings ({msg.findings.length})</summary>
                      <div className="chat-findings-list">
                        {msg.findings.slice(0, 10).map((f, i) => (
                          <div key={i} className="chat-finding-item">
                            <span className="finding-type">{f.type}</span>
                            <span className="finding-detail">{JSON.stringify(f.detail)}</span>
                          </div>
                        ))}
                        {msg.findings.length > 10 && (
                          <div className="text-muted" style={{ fontSize: 11, marginTop: 4 }}>
                            ... and {msg.findings.length - 10} more
                          </div>
                        )}
                      </div>
                    </details>
                  )}
                  <div className="chat-time">
                    {new Date(msg.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              </div>
            );
          })}
          {pendingParams && (
            <div className="chat-message chat-assistant">
              <div className="chat-avatar">AI</div>
              <div className="chat-bubble">
                <div className="chat-action-card">
                  <div className="chat-action-header">
                    <TerminalIcon style={{ width: 14, height: 14, color: 'var(--text-muted)' }} />
                    <span className="mono" style={{ color: 'var(--text-primary)', fontWeight: 700, fontSize: 14 }}>
                      {pendingParams.tool_name}
                    </span>
                    <span className={`badge ${pendingParams.action_kind === 'install' ? 'badge-blue' : preview.command ? 'badge-blue' : 'badge-danger'}`} style={{ fontSize: 10 }}>
                      {pendingParams.action_kind === 'install' ? 'INSTALL' : preview.command ? 'VALID' : 'INVALID'}
                    </span>
                  </div>
                  {pendingParams.action_kind === 'install' ? (
                    <>
                      <p className="text-muted" style={{ fontSize: 12, margin: '4px 0 10px' }}>
                        Capability <strong className="mono">{pendingParams.capability}</strong> has no healthy
                        implementation on this host. Confirming will install and verify{' '}
                        <strong className="mono">{pendingParams.tool_name}</strong>, then propose the scan
                        parameters for a second confirmation.
                      </p>
                      {(pendingParams.requirements?.length ?? 0) > 0 && (
                        <div className="text-muted" style={{ fontSize: 12, marginBottom: 8 }}>
                          Requirements: {pendingParams.requirements?.join(', ')}
                        </div>
                      )}
                      {pendingParams.install_command && (
                        <div className="terminal" style={{ marginTop: 8 }}>
                          <div className="terminal-header">
                            <span className="terminal-dots"><span /><span /><span /></span>
                            <span className="terminal-title">install</span>
                          </div>
                          <div className="terminal-body mono" style={{ fontSize: 12 }}>
                            {pendingParams.install_command}
                          </div>
                        </div>
                      )}
                      {pendingParams.verification_command && (
                        <div className="terminal" style={{ marginTop: 8 }}>
                          <div className="terminal-header">
                            <span className="terminal-dots"><span /><span /><span /></span>
                            <span className="terminal-title">verify</span>
                          </div>
                          <div className="terminal-body mono" style={{ fontSize: 12 }}>
                            {pendingParams.verification_command}
                          </div>
                        </div>
                      )}
                      <div className="confirm-actions">
                        <button
                          className="btn btn-primary"
                          onClick={handleConfirmParamsExecute}
                          disabled={confirmBusy}
                        >
                          {confirmBusy ? (
                            <>
                              <span className="spinner" />
                              Installing…
                            </>
                          ) : (
                            <>
                              <SendIcon />
                              Install &amp; verify tool
                            </>
                          )}
                        </button>
                        <button
                          className="btn btn-secondary"
                          onClick={handleCancelParams}
                          disabled={confirmBusy}
                        >
                          Cancel
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                  <p className="text-muted" style={{ fontSize: 12, margin: '4px 0 10px' }}>
                    These are the params the AI wants to use. <span className="default-pill">DEFAULT</span> means the
                    value comes from the tool registry — keep it or override it below.
                  </p>
                  <div className="param-list">
                    {(() => {
                      const tool = tools.find(t => t.name === pendingParams.tool_name);
                      if (!tool) {
                        return (
                          <div className="text-muted mono" style={{ fontSize: 12 }}>
                            {JSON.stringify(pendingParams.params)}
                          </div>
                        );
                      }
                      return Object.keys(tool.allowed_params).map(key => {
                        const toolDefault = tool.defaults?.[key];
                        const value = pendingParams.params[key] ?? '';
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
                              onChange={e => handlePendingParamChange(key, e.target.value)}
                            />
                          </div>
                        );
                      });
                    })()}
                  </div>
                  {preview.command && preview.command.length > 0 && (
                    <div className="terminal" style={{ marginTop: 12 }}>
                      <div className="terminal-header">
                        <span className="terminal-dots"><span /><span /><span /></span>
                        <span className="terminal-title">command</span>
                      </div>
                      <div className="terminal-body mono" style={{ fontSize: 12 }}>
                        {preview.command.join(' ')}
                      </div>
                    </div>
                  )}
                  {preview.error && (
                    <div className="error-box" style={{ marginTop: 12 }}>
                      <span>{preview.error}</span>
                    </div>
                  )}
                  <div className="confirm-actions">
                    <button
                      className="btn btn-primary"
                      onClick={handleConfirmParamsExecute}
                      disabled={confirmBusy || !preview.command}
                    >
                      {confirmBusy ? (
                        <>
                          <span className="spinner" />
                          Executing…
                        </>
                      ) : (
                        <>
                          <SendIcon />
                          Execute with these params
                        </>
                      )}
                    </button>
                    <button
                      className="btn btn-secondary"
                      onClick={handleCancelParams}
                      disabled={confirmBusy}
                    >
                      Cancel
                    </button>
                  </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}

          {loading && (
            <div className="chat-message chat-assistant">
              <div className="chat-avatar">AI</div>
              <div className="chat-bubble">
                <div className="chat-loading">
                  <ActivityIcon style={{ width: 14, height: 14, color: 'var(--accent-info)', marginRight: 6, animation: 'pulse 1.2s infinite' }} />
                  <span className="loading-dot">.</span>
                  <span className="loading-dot">.</span>
                  <span className="loading-dot">.</span>
                </div>
              </div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        <div className="chat-input-bar">
          <input
            type="text"
            className="chat-input"
            placeholder={isNewSession ? (!llmConnected ? 'Connect to LLM first...' : 'Enter your goal (e.g. scan target for open ports)...') : 'Send a message or continue...'}
            value={inputText}
            onChange={e => setInputText(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading || sessionLoading}
            aria-label="Message"
          />
          <button
            className="btn btn-primary"
            onClick={isNewSession ? handleStartSession : handleSendMessage}
            disabled={loading || sessionLoading || !inputText.trim() || (!isNewSession && !sessionId) || (isNewSession && !llmConnected)}
            style={{ whiteSpace: 'nowrap' }}
          >
            {sessionLoading ? (
              <>
                <span className="spinner" />
                Starting…
              </>
            ) : loading ? (
              <>
                <span className="spinner" />
                Processing…
              </>
            ) : (
              <>
                <SendIcon />
                {isNewSession ? 'Start' : 'Send'}
              </>
            )}
          </button>
        </div>
      </div>

      <div className="alert alert-info" style={{ marginTop: 16 }}>
        <InfoIcon />
        <span>
          The LLM only proposes structured tool calls mapped to the registry. It never touches
          Docker or the shell directly, and it never sees raw tool output — only parsed findings.
        </span>
      </div>
    </div>
  );
}
