import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import MetricCard from '../components/ui/MetricCard';

const severityOrder = [
  ['critical', 'Critical'],
  ['high', 'High'],
  ['medium', 'Medium'],
  ['low', 'Low'],
  ['info', 'Info'],
];

function numberOrFallback(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function formatDate(value) {
  if (!value) return 'not recorded';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'not recorded';
  return date.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function toneForStatus(status) {
  const value = String(status || '').toLowerCase();
  if (['completed', 'ready', 'online'].includes(value)) return 'emerald';
  if (['running', 'loading'].includes(value)) return 'blue';
  if (['failed', 'offline', 'error', 'unavailable'].includes(value)) return 'red';
  return 'slate';
}

function SeverityBars({ severity }) {
  const total = severityOrder.reduce((sum, [key]) => sum + numberOrFallback(severity?.[key]), 0);
  return (
    <div className="severity-bars">
      {severityOrder.map(([key, label]) => {
        const count = numberOrFallback(severity?.[key]);
        const width = total > 0 ? Math.max(6, Math.round((count / total) * 100)) : 0;
        return (
          <div className="severity-bar-row" key={key}>
            <span>{label}</span>
            <div className="severity-track">
              <i className={`severity-fill severity-fill-${key}`} style={{ width: `${width}%` }} />
            </div>
            <strong>{count}</strong>
          </div>
        );
      })}
    </div>
  );
}

export default function Overview({ onNavigate, stats, overview, overviewState }) {
  const service = overview?.service || {};
  const storage = overview?.storage || {};
  const activeScans = overview?.active_scans || {};
  const capabilities = overview?.capabilities || {};
  const risk = overview?.risk || {};
  const severity = risk.severity || {};
  const recentScans = activeScans.recent || [];
  const runningScans = numberOrFallback(activeScans.running);
  const activeTotal = numberOrFallback(activeScans.total);
  const requestCount = numberOrFallback(storage.request_count, stats?.requests || 0);
  const findingCount = numberOrFallback(risk.total_findings, stats?.findings || 0);
  const highSignal = numberOrFallback(severity.critical) + numberOrFallback(severity.high);
  const dastCount = numberOrFallback(capabilities.dast_module_count, 18);
  const importerCount = (capabilities.api_importers || []).length || 4;
  const storageStatus = storage.status || (overviewState === 'ready' ? 'ready' : overviewState || 'local');
  const serviceStatus = service.status || (overviewState === 'ready' ? 'online' : overviewState || 'standby');
  const semgrepReady = Boolean(capabilities.semgrep?.ready);

  return (
    <div className="page-stack overview-page">
      <section className="command-hero">
        <div className="command-copy">
          <span className="eyebrow">VA + Proof Scanner</span>
          <h1>Wraith v4 Command Center</h1>
          <p>
            Run DAST, SAST, manual testing, proof tasks, and report exports from one
            evidence-first workspace. The dashboard below reflects the live local API
            when it is available.
          </p>
          <div className="button-row">
            <Button size="lg" onClick={() => onNavigate('mode')}>Start Scan</Button>
            <Button size="lg" variant="secondary" onClick={() => onNavigate('manual')}>Manual Workbench</Button>
            <Button size="lg" variant="ghost" onClick={() => onNavigate('repository')}>Repository Scan</Button>
          </div>
        </div>
        <div className="mission-panel">
          <div className="mission-header">
            <span className="eyebrow">Runtime</span>
            <Badge tone={toneForStatus(serviceStatus)}>{serviceStatus}</Badge>
          </div>
          <div className="mission-grid">
            <div>
              <span>Current scan</span>
              <strong>{stats?.scanId || 'ready'}</strong>
            </div>
            <div>
              <span>Storage</span>
              <strong>{storageStatus}</strong>
            </div>
            <div>
              <span>Running</span>
              <strong>{runningScans}</strong>
            </div>
            <div>
              <span>Semgrep</span>
              <strong>{semgrepReady ? 'ready' : 'missing'}</strong>
            </div>
          </div>
          <div className="mission-line">
            <span />
            <code>{storage.path || 'reports/wraith.sqlite3'}</code>
          </div>
        </div>
      </section>

      <div className="metric-grid overview-metrics">
        <MetricCard label="Active Scans" value={activeTotal} detail={`${runningScans} running`} tone={runningScans ? 'blue' : 'cyan'} />
        <MetricCard label="Critical + High" value={highSignal} detail="priority findings" tone={highSignal ? 'red' : 'emerald'} />
        <MetricCard label="Evidence Requests" value={requestCount} detail="stored corpus rows" tone="blue" />
        <MetricCard label="Findings Indexed" value={findingCount} detail="active memory total" tone={findingCount ? 'amber' : 'slate'} />
        <MetricCard label="DAST Modules" value={dastCount} detail="crawler, API, SPA" />
        <MetricCard label="API Importers" value={importerCount} detail="OpenAPI, HAR, GraphQL" tone="emerald" />
      </div>

      <PageHeader
        eyebrow="Operator Snapshot"
        title="What Needs Attention"
        description="Risk posture, recent activity, and readiness checks for the local scanner runtime."
      />
      <div className="overview-grid">
        <Card title="Risk Posture" eyebrow="Severity">
          <SeverityBars severity={severity} />
        </Card>
        <Card title="Recent Scans" eyebrow="Activity">
          <div className="recent-scan-list">
            {recentScans.length > 0 ? recentScans.map((scan) => (
              <button
                type="button"
                key={scan.scan_id}
                className="recent-scan-row"
                onClick={() => onNavigate(scan.mode === 'sast' ? 'repository' : 'automated-workspace')}
              >
                <span>
                  <strong>{scan.target || 'Untitled target'}</strong>
                  <em>{scan.scan_id} / {scan.scan_type || scan.mode}</em>
                </span>
                <span>
                  <Badge tone={toneForStatus(scan.status)}>{scan.status}</Badge>
                  <code>{formatDate(scan.completed_at || scan.started_at)}</code>
                </span>
              </button>
            )) : (
              <div className="empty-inline">
                <span className="material-symbols-outlined">radar</span>
                <p>No scans in memory yet. Start a scan to populate live activity.</p>
              </div>
            )}
          </div>
        </Card>
        <Card title="Readiness Matrix" eyebrow="System" className="overview-wide">
          <div className="readiness-grid">
            <div>
              <span className="material-symbols-outlined">storage</span>
              <strong>Corpus Storage</strong>
              <p>{storageStatus === 'ready' ? 'SQLite corpus is writable and indexed.' : 'Storage is not reporting ready status.'}</p>
              <Badge tone={toneForStatus(storageStatus)}>{storageStatus}</Badge>
            </div>
            <div>
              <span className="material-symbols-outlined">code_blocks</span>
              <strong>SAST Engine</strong>
              <p>{semgrepReady ? 'Semgrep is available for repository analysis.' : 'Install Semgrep for full repository analysis.'}</p>
              <Badge tone={semgrepReady ? 'emerald' : 'amber'}>{semgrepReady ? 'ready' : 'optional'}</Badge>
            </div>
            <div>
              <span className="material-symbols-outlined">verified_user</span>
              <strong>Proof Workflow</strong>
              <p>Safe proof tasks, evidence bundles, and report exports are wired into the same corpus.</p>
              <Badge tone="emerald">enabled</Badge>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
