import { useEffect, useState, type JSX } from 'react';
import { ScopeForm } from './components/ScopeForm';
import { ScopeViewer } from './components/ScopeViewer';
import { ValidatePanel } from './components/ValidatePanel';
import { ToolRegistry } from './components/ToolRegistry';
import { SandboxPanel } from './components/SandboxPanel';
import { ApprovalsPanel } from './components/ApprovalsPanel';
import { OrchestratorPanel } from './components/OrchestratorPanel';
import {
  ShieldIcon,
  ScopeIcon,
  EyeIcon,
  WrenchIcon,
  BoxIcon,
  CheckCircleIcon,
  BrainIcon,
  MenuIcon,
} from './components/icons';
import type { ScopeData } from './hooks/useApi';
import './App.css';

type Tab = 'create' | 'view' | 'validate' | 'tools' | 'sandbox' | 'approvals' | 'orchestrator';

const TABS: { key: Tab; label: string; icon: (props: any) => JSX.Element; section: string }[] = [
  { key: 'create', label: 'New Scope', icon: ScopeIcon, section: 'Engagement' },
  { key: 'view', label: 'Scope Viewer', icon: EyeIcon, section: 'Engagement' },
  { key: 'validate', label: 'Validate', icon: CheckCircleIcon, section: 'Engagement' },
  { key: 'tools', label: 'Tool Registry', icon: WrenchIcon, section: 'Operations' },
  { key: 'sandbox', label: 'Sandbox', icon: BoxIcon, section: 'Operations' },
  { key: 'approvals', label: 'Approvals', icon: ShieldIcon, section: 'Governance' },
  { key: 'orchestrator', label: 'AI Assistant', icon: BrainIcon, section: 'Intelligence' },
];

type HealthState = 'checking' | 'ok' | 'down';

function App() {
  const [tab, setTab] = useState<Tab>('create');
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [health, setHealth] = useState<HealthState>('checking');

  useEffect(() => {
    let alive = true;
    fetch('http://localhost:8000/api/health')
      .then(res => res.json())
      .then(() => alive && setHealth('ok'))
      .catch(() => alive && setHealth('down'));
    return () => {
      alive = false;
    };
  }, []);

  const handleScopeCreated = (_scope: ScopeData) => {
    setTab('view');
  };

  const selectTab = (t: Tab) => {
    setTab(t);
    setMobileOpen(false);
  };

  const activeTab = TABS.find(t => t.key === tab)!;

  const navItems = (
    <>
      {TABS.map(({ key, label, icon: Icon }) => (
        <button
          key={key}
          className={`nav-item ${tab === key ? 'active' : ''}`}
          onClick={() => selectTab(key)}
          aria-current={tab === key ? 'page' : undefined}
        >
          <Icon />
          <span className="nav-label">{label}</span>
        </button>
      ))}
    </>
  );

  return (
    <div className="app-shell">
      {mobileOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      <aside className={`sidebar ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar-brand">
          <span className="brand-mark">
            <ShieldIcon />
          </span>
          {!collapsed && (
            <span className="brand-text">
              <span className="brand-name">REDCON</span>
              <span className="brand-sub">AI Red Team Platform</span>
            </span>
          )}
        </div>

        <nav className="sidebar-nav" aria-label="Primary">
          {navItems}
        </nav>

        <div className="sidebar-footer">
          <div className="system-health" title={health === 'ok' ? 'Backend online' : 'Backend offline'}>
            <span className={`health-dot ${health}`} />
            {!collapsed && (
              <span className="health-label">
                <span className="health-status">Backend</span>
                <span
                  className="health-caption"
                  style={{ color: health === 'ok' ? 'var(--accent-success)' : health === 'down' ? 'var(--accent-danger)' : 'var(--accent-warning)' }}
                >
                  {health === 'ok' ? 'Online' : health === 'down' ? 'Offline' : 'Checking…'}
                </span>
              </span>
            )}
          </div>
        </div>
      </aside>

      <div className="app-main">
        <header className="topbar">
          <button
            className="topbar-toggle"
            onClick={() => setCollapsed(c => !c)}
            aria-label="Toggle sidebar"
            title="Toggle sidebar"
          >
            <MenuIcon />
          </button>
          <div className="topbar-crumb">
            <span className="crumb-route">{activeTab.section}</span>
            <span className="crumb-title">{activeTab.label}</span>
          </div>
          <div className="topbar-spacer" />
          <div className="topbar-meta">
            <span className="phase-chip">
              <span className="chip-dot" />
              PHASE 6 · INVESTIGATION
            </span>
            <span className="env-chip">LOCAL</span>
          </div>
        </header>

        <main className="app-content">
          <div className="page">
            {tab === 'create' && <ScopeForm onCreated={handleScopeCreated} />}
            {tab === 'view' && <ScopeViewer />}
            {tab === 'validate' && <ValidatePanel />}
            {tab === 'tools' && <ToolRegistry />}
            {tab === 'sandbox' && <SandboxPanel />}
            {tab === 'approvals' && <ApprovalsPanel />}
            {tab === 'orchestrator' && <OrchestratorPanel />}
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
