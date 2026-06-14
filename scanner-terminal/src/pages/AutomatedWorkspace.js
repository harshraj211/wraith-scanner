import React from 'react';
import WorkflowHero from '../components/layout/WorkflowHero';
import Button from '../components/ui/Button';
import EmptyState from '../components/ui/EmptyState';

const zeroSeverity = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

function hostFromTarget(value) {
  try {
    return new URL(String(value || '')).hostname || String(value || '');
  } catch (_error) {
    return String(value || '').replace(/^https?:\/\//, '').split('/')[0];
  }
}

function numberOr(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function calculateRiskScore(counts, totalFindings) {
  if (!totalFindings) return 0;
  const weighted = (counts.critical || 0) * 16
    + (counts.high || 0) * 8
    + (counts.medium || 0) * 3
    + (counts.low || 0);
  return Math.max(1, Math.min(99, Math.round((weighted / Math.max(1, totalFindings)) * 100)));
}

function severityLabel(severity) {
  const value = String(severity || 'info').toLowerCase();
  return zeroSeverity[value] !== undefined ? value : 'info';
}

function severityCountsFromFindings(findings) {
  return (findings || []).reduce((out, finding) => {
    const severity = severityLabel(finding.severity);
    out[severity] += 1;
    return out;
  }, { ...zeroSeverity });
}

function shortElapsed(scanStatus) {
  if (scanStatus?.elapsed) return scanStatus.elapsed;
  const started = scanStatus?.started_at || scanStatus?.created_at;
  if (!started) return '--:--:--';
  const delta = Math.max(0, Date.now() - new Date(started).getTime());
  const totalSeconds = Math.floor(delta / 1000);
  const hours = String(Math.floor(totalSeconds / 3600)).padStart(2, '0');
  const minutes = String(Math.floor((totalSeconds % 3600) / 60)).padStart(2, '0');
  const seconds = String(totalSeconds % 60).padStart(2, '0');
  return `${hours}:${minutes}:${seconds}`;
}

function findingRows(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return [];
  return findings.slice(0, 8).map((finding, index) => [
    severityLabel(finding.severity),
    finding.title || finding.name || 'Finding',
    finding.target_url || finding.normalized_endpoint || finding.endpoint || '-',
    finding.age || finding.discovered_at || finding.created_at || '-',
  ]);
}

function eventRows(progressEvents) {
  if (!Array.isArray(progressEvents) || progressEvents.length === 0) return [];
  return progressEvents.slice(0, 7).map((event) => {
    const date = event.timestamp ? new Date(event.timestamp) : null;
    const time = date && !Number.isNaN(date.getTime())
      ? date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
      : 'now';
    return [
      time,
      severityLabel(event.type || event.status || 'info'),
      event.message || event.detail || 'Scan event',
      event.phase || event.scan_id || '',
      event.target || '',
    ];
  });
}

function buildModuleRows(scanStatus) {
  if (!scanStatus) return [];
  const moduleSource = scanStatus.module_status || scanStatus.modules || scanStatus.module_progress || [];
  const rows = Array.isArray(moduleSource)
    ? moduleSource
    : Object.entries(moduleSource).map(([name, value]) => ({ name, ...(typeof value === 'object' ? value : { status: value }) }));

  const mappedRows = rows.map((module) => {
    const name = module.name || module.label || module.module || module.id || 'Module';
    const moduleStatus = String(module.status || module.state || '-').toLowerCase();
    const progress = Math.round(percent(module.progress ?? module.percent ?? module.progress_percent ?? 0));
    return [name, moduleStatus, progress, module.icon || moduleIcon(name)];
  });

  if (mappedRows.length) return mappedRows;

  const overall = scanProgress(scanStatus);
  const phaseModules = [
    ['Crawler', 'travel_explore'],
    ['Discovery', 'radar'],
    ['Active Scanner', 'my_location'],
    ['Verification', 'verified_user'],
    ['Reporting', 'article'],
  ];

  return phaseModules.map(([name, icon], index) => {
    const start = index * 20;
    const value = Math.round(percent(((overall - start) / 20) * 100));
    const status = value >= 100
      ? 'completed'
      : value > 0 || (overall > 0 && index === 0)
        ? 'running'
        : 'queued';
    return [name, status, value, icon];
  });
}

function healthRows(scanStatus) {
  if (!scanStatus) return [];
  const authHealth = scanStatus.auth_health || {};
  const imports = scanStatus.api_imports || {};
  const deepState = scanStatus.deep_state_summary || {};
  const nuclei = scanStatus.nuclei_summary || {};
  const rows = [
    ['Scan Status', scanStatus.status === 'failed' ? 'fail' : scanStatus.status === 'completed' ? 'pass' : 'warn', scanStatus.error || scanStatus.status || 'idle'],
  ];
  if (Object.keys(authHealth).length) {
    rows.push(['Auth Health', authHealth.status === 'passed' ? 'pass' : authHealth.status === 'failed' ? 'fail' : 'warn', authHealth.reason || authHealth.status || '-']);
  }
  if (Object.keys(imports).length) {
    rows.push(['API Imports', Object.values(imports).some((value) => Array.isArray(value) ? value.length > 0 : Boolean(value)) ? 'pass' : 'warn', JSON.stringify(imports)]);
  }
  if (Array.isArray(scanStatus.sequence_workflows) && scanStatus.sequence_workflows.length > 0) {
    rows.push(['Sequence Workflows', 'pass', `${scanStatus.sequence_workflows.length} loaded`]);
  }
  if (Object.keys(deepState).length) {
    rows.push(['Deep State', 'pass', 'available']);
  }
  if (Object.keys(nuclei).length) {
    rows.push(['Nuclei Coverage', nuclei.raw_count ? 'pass' : 'warn', `${nuclei.raw_count || 0} matches`]);
  }
  if (scanStatus.report_path) rows.push(['Report Artifact', 'pass', 'PDF ready']);
  if (scanStatus.json_report_path) rows.push(['JSON Artifact', 'pass', 'JSON ready']);
  return rows;
}

function moduleIcon(name) {
  const value = String(name || '').toLowerCase();
  if (value.includes('crawl')) return 'travel_explore';
  if (value.includes('passive') || value.includes('policy')) return 'policy';
  if (value.includes('nuclei') || value.includes('template')) return 'hub';
  if (value.includes('evidence') || value.includes('corpus')) return 'storage';
  if (value.includes('api')) return 'api';
  return 'settings_input_component';
}

function percent(value) {
  const parsed = numberOr(value, 0);
  return Math.max(0, Math.min(100, parsed));
}

function progressFromEvents(progressEvents = []) {
  const events = Array.isArray(progressEvents) ? progressEvents : [];
  let score = 0;
  events.forEach((event) => {
    const text = `${event?.message || ''} ${event?.detail || ''} ${event?.phase || ''} ${event?.status || ''}`.toLowerCase();
    const explicit = text.match(/(\d{1,3})\s*%/);
    if (explicit) score = Math.max(score, percent(explicit[1]));
    if (/scan complete|completed|json report ready|pdf report ready|report saved/.test(text)) score = Math.max(score, 100);
    else if (/phase 3|generating report|report/.test(text)) score = Math.max(score, 88);
    else if (/phase 2|testing|active scan|vulnerabil/.test(text)) score = Math.max(score, 62);
    else if (/crawl complete|discovery|discovered|corpus/.test(text)) score = Math.max(score, 38);
    else if (/starting|started|launch|crawl/.test(text)) score = Math.max(score, 12);
  });
  if (events.length) score = Math.max(score, Math.min(92, 10 + events.length * 4));
  return score;
}

function scanProgress(scanStatus, progressEvents = []) {
  const direct = scanStatus?.progress_percent ?? scanStatus?.progress ?? scanStatus?.percent_complete;
  if (direct !== undefined && direct !== null && direct !== '') return percent(direct);
  const status = String(scanStatus?.status || '').toLowerCase();
  if (status === 'completed') return 100;
  if (status === 'failed') return Math.max(1, progressFromEvents(progressEvents));
  if (status === 'running' || status === 'active' || scanStatus?.scan_id) {
    return Math.max(8, progressFromEvents(progressEvents));
  }
  return progressFromEvents(progressEvents);
}

function buildSurfaceNodes(requests, target, findings) {
  const records = Array.isArray(requests) ? requests : [];
  const hosts = new Set();
  const methods = new Set();
  const paths = new Set();
  let apiCount = 0;
  let formCount = 0;
  let authCount = 0;
  const rootHost = hostFromTarget(target).toLowerCase();
  records.forEach((request) => {
    try {
      const parsed = new URL(request.url || '');
      if (parsed.hostname) hosts.add(parsed.hostname);
      if (parsed.pathname) paths.add(parsed.pathname);
      if (parsed.pathname.includes('/api')) apiCount += 1;
      if (/login|auth|session|token/i.test(parsed.pathname)) authCount += 1;
    } catch (_error) {
      // Ignore malformed URLs from incomplete corpus records.
    }
    if (request.method) methods.add(String(request.method).toUpperCase());
    if (request.body && String(request.body).trim()) formCount += 1;
  });
  const subdomains = Array.from(hosts).filter((host) => host.toLowerCase() !== rootHost);
  const findingCount = Array.isArray(findings) ? findings.length : 0;
  return [
    { label: 'Hosts', count: hosts.size, icon: 'developer_board', angle: -35, distance: 156, tone: 'blue' },
    { label: 'Subdomains', count: subdomains.length, icon: 'lan', angle: -68, distance: 150, tone: 'blue', showZero: true },
    { label: 'Requests', count: records.length, icon: 'dns', angle: -104, distance: 142, tone: 'blue' },
    { label: 'Paths', count: paths.size, icon: 'route', angle: 172, distance: 152, tone: 'blue' },
    { label: 'Methods', count: methods.size, icon: 'http', angle: 126, distance: 152, tone: 'blue', showZero: true },
    { label: 'APIs', count: apiCount, icon: 'api', angle: 72, distance: 150, tone: 'blue' },
    { label: 'Stateful', count: formCount, icon: 'inventory_2', angle: 35, distance: 148, tone: 'blue' },
    { label: 'Auth Paths', count: authCount, icon: 'key', angle: 0, distance: 156, tone: authCount ? 'red' : 'blue' },
    { label: 'Findings', count: findingCount, icon: 'shield', angle: -150, distance: 150, tone: findingCount ? 'red' : 'blue' },
  ].filter((node) => node.showZero || node.count > 0);
}

function buildRiskDots(findings) {
  return (findings || []).slice(0, 24).map((finding, index) => ({
    severity: severityLabel(finding.severity),
    x: 16 + ((index * 37) % 68),
    y: 18 + ((index * 23) % 62),
  }));
}

function AttackSurfaceMap({ target, nodes, dots }) {
  return (
    <div className="attack-map" aria-label="Attack surface map">
      <div className="attack-map-grid" />
      <div className="attack-map-rings">
        <i />
        <i />
        <i />
      </div>
      <div className="attack-map-axis attack-map-axis-x" />
      <div className="attack-map-axis attack-map-axis-y" />
      <div className="attack-map-core">
        <span className="material-symbols-outlined">language</span>
        <strong>{target || 'No target'}</strong>
      </div>
      {nodes.map((node) => (
        <div
          className={`attack-node attack-node-${node.tone}`}
          key={node.label}
          style={{
            '--angle': `${node.angle}deg`,
            '--distance': `${node.distance}px`,
          }}
        >
          <span className="attack-node-line" />
          <span className="attack-node-icon material-symbols-outlined">{node.icon}</span>
          <strong>{node.count}</strong>
          <em>{node.label}</em>
        </div>
      ))}
      <div className="attack-map-dots">
        {dots.map((dot, index) => (
          <span
            key={index}
            className={`risk-dot risk-dot-${dot.severity}`}
            style={{
              '--x': `${dot.x}%`,
              '--y': `${dot.y}%`,
            }}
          />
        ))}
      </div>
      {!nodes.length && !dots.length && (
        <div className="attack-map-empty">
          <strong>No attack surface data yet</strong>
          <span>Run a scan to populate discovered hosts, requests, and findings.</span>
        </div>
      )}
    </div>
  );
}

function StatCard({ icon, label, value, detail, tone = 'cyan' }) {
  return (
    <div className={`cockpit-stat cockpit-stat-${tone}`}>
      <span className="material-symbols-outlined">{icon}</span>
      <div>
        <em>{label}</em>
        <strong>{value}</strong>
        {detail && <small>{detail}</small>}
      </div>
    </div>
  );
}

function Panel({ title, eyebrow, actions, className = '', children }) {
  return (
    <section className={`cockpit-panel ${className}`.trim()}>
      <header>
        <div>
          {eyebrow && <span>{eyebrow}</span>}
          <h2>{title}</h2>
        </div>
        {actions && <div className="cockpit-panel-actions">{actions}</div>}
      </header>
      {children}
    </section>
  );
}

function ScanWorkspacePanel({ scanStatus, scanId, target, requestCount, totalFindings, modules, progressEvents, onNavigate }) {
  const progress = scanProgress(scanStatus, progressEvents);
  const status = scanStatus?.status || 'idle';
  const phases = ['Crawl', 'Discovery', 'Active Scan', 'Verify', 'Report'];
  return (
    <section className="workflow-card workflow-workspace-card">
      <header>
        <h2>2. Scan Workspace</h2>
        <p>Live scan progress from backend state.</p>
      </header>

      <div className="workflow-workspace-grid">
        <div className="workflow-progress-block">
          <div className="workflow-donut" style={{ '--value': `${progress}%` }}>
            <strong>{progress}%</strong>
          </div>
          <div className="workflow-scan-meta">
            <div className="workflow-meta"><span>Scan ID</span><strong>{scanId || 'none'}</strong></div>
            <div className="workflow-meta"><span>Target</span><strong>{target || '-'}</strong></div>
            <div className="workflow-meta"><span>Status</span><strong>{status}</strong></div>
            <div className="workflow-meta"><span>Requests</span><strong>{requestCount || '-'}</strong></div>
            <div className="workflow-meta"><span>Findings</span><strong>{totalFindings || '-'}</strong></div>
          </div>
        </div>

        <div className="workflow-phase" style={{ '--progress-width': `${progress * 0.82}%` }}>
          {phases.map((phase, index) => (
            <span className={progress >= index * 25 || (progress === 0 && index === 0 && scanStatus) ? 'active' : ''} key={phase}>
              <i />
              {phase}
            </span>
          ))}
        </div>

        <div className="workflow-table">
          <header>
            <span>Module</span>
            <span>Status</span>
            <span>Progress</span>
          </header>
          {modules.length ? modules.slice(0, 6).map(([name, moduleStatus, moduleProgress, icon]) => (
            <div key={name}>
              <span><i className="material-symbols-outlined">{icon}</i>{name}</span>
              <strong>{moduleStatus}</strong>
              <em><i style={{ width: `${percent(moduleProgress)}%` }} /></em>
            </div>
          )) : (
            <EmptyState title="No module progress yet" body="The backend has not reported per-module progress for this scan." />
          )}
        </div>

        <div className="workflow-events">
          {eventRows(progressEvents).map(([time, tone, message], index) => (
            <code key={`${time}-${message}-${index}`}>
              <span>{time}</span>
              {message || tone}
            </code>
          ))}
          {!eventRows(progressEvents).length && (
            <EmptyState title="No scan events yet" body="Socket events appear here as the backend emits progress." />
          )}
        </div>

        <Button variant="secondary" onClick={() => onNavigate('findings')} disabled={!totalFindings}>
          Open Findings
        </Button>
      </div>
    </section>
  );
}

export default function AutomatedWorkspace({
  scanStatus,
  latestScanId,
  scanPayload,
  dashboard,
  progressEvents,
  corpusRequests,
  findings = [],
  refreshStatus,
  onNavigate,
}) {
  const hasLiveScan = Boolean(latestScanId || scanStatus?.scan_id || scanStatus?.target || scanStatus?.url);
  const counts = { ...severityCountsFromFindings(findings), ...(dashboard?.severityCounts || {}) };
  const totalFindings = numberOr(dashboard?.totalFindings, findings.length);
  const requestCount = numberOr(corpusRequests?.length, 0);
  const activeTargetValue = scanStatus?.url || scanStatus?.target || '';
  const displayTarget = hostFromTarget(activeTargetValue);
  const scanId = latestScanId || scanStatus?.scan_id || '';
  const status = scanStatus?.status || (hasLiveScan ? 'active' : 'idle');
  const riskScore = calculateRiskScore(counts, totalFindings);
  const modules = buildModuleRows(scanStatus);
  const currentHealthRows = healthRows(scanStatus);
  const confirmedFindings = numberOr(dashboard?.confirmedFindings || dashboard?.confirmed, 0);
  const surfaceNodes = buildSurfaceNodes(corpusRequests, activeTargetValue, findings);
  const riskDots = buildRiskDots(findings);
  const timeline = Array.isArray(dashboard?.timeline) ? dashboard.timeline.slice(-14) : [];
  const healthFailures = currentHealthRows.filter(([, state]) => state === 'fail').length;
  const healthWarnings = currentHealthRows.filter(([, state]) => state === 'warn').length;
  const artifactCount = Number(Boolean(scanStatus?.report_path)) + Number(Boolean(scanStatus?.json_report_path));
  const workerCount = scanStatus?.workers || scanStatus?.threads;

  return (
    <div className="cockpit-page workflow-page">
      <WorkflowHero
        icon="space_dashboard"
        eyebrow="Automated"
        title="Cockpit"
        description="Inspect the active scan, attack surface, findings, health checks, and backend events."
        active="automated-workspace"
        onNavigate={onNavigate}
        actions={<Button variant="secondary" onClick={refreshStatus} disabled={!latestScanId}>Refresh</Button>}
      />

      <ScanWorkspacePanel
        scanStatus={scanStatus}
        scanId={scanId}
        target={displayTarget}
        requestCount={requestCount}
        totalFindings={totalFindings}
        modules={modules}
        progressEvents={progressEvents}
        onNavigate={onNavigate}
      />

      <section className="cockpit-stage">
        <div className="cockpit-topline">
          <div className="cockpit-active-scan">
            <span className={hasLiveScan ? 'cockpit-live-dot' : 'cockpit-idle-dot'} />
            <div>
              <em>Active Scan</em>
              <strong>{displayTarget || 'No active scan'}</strong>
              <code>{scanId || 'Run a scan from Scan Setup'}</code>
            </div>
          </div>
          <div className="cockpit-top-metric">
            <em>Elapsed</em>
            <strong>{shortElapsed(scanStatus)}</strong>
            <span className="material-symbols-outlined">timer</span>
          </div>
          <div className="cockpit-top-metric">
            <em>Status</em>
            <strong className="text-cyan">{status}</strong>
            {hasLiveScan && <span className="scan-pulse" />}
          </div>
          <div className="cockpit-top-metric">
            <em>Engine</em>
            <strong>{scanStatus?.engine || 'WRAITH'}</strong>
            <span className="material-symbols-outlined">shield</span>
          </div>
          <div className="cockpit-top-metric">
            <em>Workers</em>
            <strong>{workerCount || '-'}</strong>
            {workerCount ? <span className="thread-bars"><i /><i /><i /><i /><i /></span> : <span className="thread-bars-empty">idle</span>}
          </div>
          <div className="cockpit-risk">
            <div>
              <em>Risk Score</em>
              <strong>{riskScore}</strong>
              <span>/100</span>
            </div>
            <div className="risk-sparkline">
              {timeline.length ? timeline.map((value, index) => (
                <i key={index} style={{ height: `${Math.max(4, percent(value))}%` }} />
              )) : <span>No trend yet</span>}
            </div>
          </div>
        </div>

        <div className="cockpit-stat-grid">
          <StatCard icon="monitor_heart" label="Target Health" value={hasLiveScan ? `${healthFailures} fail / ${healthWarnings} warn` : 'Idle'} detail={hasLiveScan ? 'Backend health checks' : 'No scan selected'} tone={healthFailures ? 'red' : healthWarnings ? 'amber' : 'green'} />
          <StatCard icon="my_location" label="Requests Captured" value={requestCount} detail="Corpus records" tone="cyan" />
          <StatCard icon="shield" label="Findings" value={totalFindings} detail={`${confirmedFindings} verified / ${counts.critical} critical / ${counts.high} high`} tone={counts.critical || counts.high ? 'red' : 'blue'} />
          <StatCard icon="radar" label="Events" value={progressEvents?.length || 0} detail="Socket/backend events" tone="green" />
          <StatCard icon="article" label="Artifacts" value={artifactCount} detail="PDF / JSON reports" tone="amber" />
        </div>

        <div className="cockpit-main-grid">
          <Panel
            title="Attack Surface Map"
            className="attack-surface-panel"
            actions={(
              <button type="button" aria-label="Refresh attack surface" onClick={refreshStatus} disabled={!latestScanId}>
                <span className="material-symbols-outlined">sync</span>
              </button>
            )}
          >
            <AttackSurfaceMap target={displayTarget} nodes={surfaceNodes} dots={riskDots} />
            <footer className="map-legend">
              <span><i className="risk-dot-low" />Low Risk</span>
              <span><i className="risk-dot-medium" />Medium Risk</span>
              <span><i className="risk-dot-high" />High Risk</span>
              <span><i className="risk-dot-critical" />Critical</span>
            </footer>
          </Panel>

          <Panel
            title={`Scan Modules (${modules.length})`}
            className="scan-modules-panel"
            actions={<button type="button" aria-label="Open modules" onClick={() => onNavigate('nuclei')}><span className="material-symbols-outlined">open_in_new</span></button>}
          >
            {modules.length ? (
              <div className="module-table">
                <div className="module-row module-head">
                  <span>Module</span>
                  <span>Status</span>
                  <span>Progress</span>
                </div>
                {modules.map(([name, moduleStatus, progress, icon]) => (
                  <div className="module-row" key={name}>
                    <span><i className="material-symbols-outlined">{icon}</i>{name}</span>
                    <strong className={`module-status-${moduleStatus}`}>{moduleStatus}</strong>
                    <span className="module-progress">
                      <em>{progress ? `${progress}%` : '-'}</em>
                      <i><b style={{ width: `${percent(progress)}%` }} /></i>
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No modules running" body="Start a scan to see backend module progress." />
            )}
            <button className="cockpit-link" type="button" onClick={() => onNavigate('nuclei')}>Open Nuclei & CVE</button>
          </Panel>

          <Panel title="Live Event Stream" className="event-stream-panel">
            <div className="event-stream">
              {eventRows(progressEvents).map(([time, tone, message, path, host], index) => (
                <div className="event-row" key={`${time}-${message}-${index}`}>
                  <time>{time}</time>
                  <strong className={`severity-text-${tone}`}>[{tone}]</strong>
                  <span>{message}</span>
                  <code>{path}</code>
                  <code>{host}</code>
                </div>
              ))}
              {eventRows(progressEvents).length === 0 && (
                <div className="event-row event-row-empty">
                  <span>No live events yet</span>
                  <code>Start or refresh a scan to stream backend progress.</code>
                </div>
              )}
            </div>
            <footer><span className={hasLiveScan ? 'cockpit-live-dot' : 'cockpit-idle-dot'} />{hasLiveScan ? 'Connected to scan state' : 'Waiting for scan'}</footer>
          </Panel>

          <Panel
            title="Target Health Checks"
            className="health-panel"
            actions={<button className="cockpit-link" type="button" onClick={() => onNavigate('evidence')}>View All</button>}
          >
            <div className="health-list">
              {currentHealthRows.map(([label, state, detail]) => (
                <div className="health-row" key={label}>
                  <span className={`health-icon health-${state} material-symbols-outlined`}>
                    {state === 'pass' ? 'check_circle' : state === 'warn' ? 'warning' : 'cancel'}
                  </span>
                  <strong>{label}</strong>
                  <em className={`health-state-${state}`}>{state}</em>
                  <code>{detail}</code>
                </div>
              ))}
              {!currentHealthRows.length && <EmptyState title="No health checks yet" body="Health rows appear after the backend returns scan status." />}
            </div>
          </Panel>

          <Panel
            title={`Findings Triage (${totalFindings})`}
            className="findings-panel"
            actions={(
              <div className="triage-tabs">
                {['All', 'Critical', 'High', 'Medium', 'Low'].map((item) => <button type="button" key={item}>{item}</button>)}
              </div>
            )}
          >
            <div className="triage-table">
              <div className="triage-row triage-head">
                <span>Severity</span>
                <span>Title</span>
                <span>Asset</span>
                <span>Age</span>
              </div>
              {findingRows(findings).map(([severity, title, asset, age], index) => (
                <button className="triage-row" type="button" key={`${title}-${index}`} onClick={() => onNavigate('findings')}>
                  <span className={`severity-chip severity-chip-${severity}`}>{severity}</span>
                  <strong>{title}</strong>
                  <code>{asset}</code>
                  <em>{age}</em>
                </button>
              ))}
              {findingRows(findings).length === 0 && (
                <div className="triage-row triage-empty">
                  <span>No findings</span>
                  <strong>Backend has not returned findings for this scan.</strong>
                  <code>{displayTarget || '-'}</code>
                  <em>-</em>
                </div>
              )}
            </div>
            <button className="cockpit-link" type="button" onClick={() => onNavigate('findings')}>View all findings</button>
          </Panel>
        </div>
      </section>

      <section className="cockpit-controlbar">
        <div>
          <span>Scan Control</span>
          <button type="button" disabled><span className="material-symbols-outlined">pause</span>Pause</button>
          <button type="button" disabled><span className="material-symbols-outlined">stop</span>Stop</button>
          <button type="button" onClick={() => onNavigate('reports')}><span className="material-symbols-outlined">assessment</span>Open Reports</button>
        </div>
        <div>
          <span>Scan Profile</span>
          <strong>{scanStatus?.scan_type || scanStatus?.mode || '-'}</strong>
        </div>
        <div>
          <span>Target</span>
          <strong><span className="material-symbols-outlined">language</span>{displayTarget || '-'}</strong>
        </div>
        <div>
          <span>Scope</span>
          <strong>{scanStatus?.scope || '-'}</strong>
        </div>
        <div>
          <span>Output</span>
          <strong>{hasLiveScan ? 'Backend state' : 'Idle'}</strong>
        </div>
        <Button variant="secondary" onClick={refreshStatus} disabled={!latestScanId}>Refresh</Button>
      </section>
    </div>
  );
}
