import React, { useMemo, useState } from 'react';
import WorkflowHero from '../components/layout/WorkflowHero';
import Button from '../components/ui/Button';
import EmptyState from '../components/ui/EmptyState';
import TerminalPanel from '../components/ui/TerminalPanel';

function statusLabel(scanStatus, repoState) {
  if (scanStatus?.status) return scanStatus.status;
  if (repoState === 'scanning' || repoState === 'started') return 'running';
  if (repoState === 'error') return 'failed';
  return 'idle';
}

function statusTone(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'completed') return 'complete';
  if (value === 'failed' || value === 'error') return 'failed';
  if (value === 'running' || value === 'started' || value === 'scanning') return 'running';
  return 'idle';
}

function formatNumber(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number.toLocaleString() : '0';
}

function findingRows(scanStatus) {
  const rows = scanStatus?.canonical_findings || scanStatus?.findings || [];
  return Array.isArray(rows) ? rows.slice(0, 5) : [];
}

const LANGUAGE_COLORS = ['#31e995', '#b6ff4d', '#f8c63c', '#ff7a45', '#ff5f6d', '#f472b6'];

const LANGUAGE_LABELS = {
  c_cpp_header: 'C/C++ Header',
  cpp: 'C++',
  csharp: 'C#',
  javascript: 'JavaScript',
  typescript: 'TypeScript',
};

function displayLanguage(name = '') {
  const key = String(name || '').trim().toLowerCase();
  if (!key) return 'Unknown';
  if (LANGUAGE_LABELS[key]) return LANGUAGE_LABELS[key];
  return key
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function languageEntries(source) {
  if (!source) return [];
  if (Array.isArray(source)) {
    return source
      .map((item) => ({
        rawName: item.name || item.language || item.label,
        value: Number(item.percent ?? item.percentage ?? item.value ?? item.count ?? 0),
      }))
      .filter((item) => item.rawName && Number.isFinite(item.value));
  }
  return Object.entries(source)
    .map(([rawName, value]) => ({ rawName, value: Number(value || 0) }))
    .filter((item) => item.rawName && Number.isFinite(item.value));
}

function languageRows(stack) {
  const percentageRows = languageEntries(stack?.languages || stack?.language_percentages || stack?.language_breakdown);
  const countRows = languageEntries(stack?.language_counts);
  const rows = percentageRows.length ? percentageRows : countRows;
  if (!rows.length) {
    const primary = String(stack?.primary_language || '').toLowerCase();
    return primary && primary !== 'unknown'
      ? [{ rawName: primary, name: displayLanguage(primary), value: 100, percent: 100, count: null }]
      : [];
  }

  const total = rows.reduce((sum, row) => sum + Number(row.value || 0), 0) || 1;
  const valuesArePercentages = percentageRows.length > 0;
  const countsByName = Object.fromEntries(
    countRows.map((row) => [String(row.rawName).toLowerCase(), row.value]),
  );

  return rows
    .map((row) => {
      const key = String(row.rawName).toLowerCase();
      const percent = valuesArePercentages ? row.value : (row.value / total) * 100;
      return {
        rawName: row.rawName,
        name: displayLanguage(row.rawName),
        value: row.value,
        percent,
        count: countsByName[key] ?? (valuesArePercentages ? null : row.value),
      };
    })
    .filter((row) => row.percent > 0)
    .sort((a, b) => b.percent - a.percent);
}

function repoLabel(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.hostname}${parsed.pathname}`.replace(/\/$/, '');
  } catch (_error) {
    return url || 'not set';
  }
}

function languageStyle(rows) {
  let cursor = 0;
  const stops = rows.slice(0, 6).map((row, index) => {
    const start = cursor;
    cursor += Number(row.percent || 0);
    return `${LANGUAGE_COLORS[index % LANGUAGE_COLORS.length]} ${start.toFixed(2)}% ${Math.min(cursor, 100).toFixed(2)}%`;
  });
  return { '--language-stops': stops.join(', ') || '#173142 0 100%' };
}

export default function RepositoryScan({
  repoForm,
  updateRepoForm,
  submitRepoScan,
  repoState,
  latestScanId,
  scanStatus,
  progressEvents,
  onDownloadPdf,
  onDownloadJson,
  onOpenReports,
  onNavigate,
}) {
  const [showToken, setShowToken] = useState(false);
  const status = statusLabel(scanStatus, repoState);
  const lowerStatus = String(status || '').toLowerCase();
  const isCompleted = lowerStatus === 'completed';
  const isRunning = ['running', 'started', 'scanning'].includes(lowerStatus);
  const isSastScan = scanStatus?.mode === 'sast' || String(scanStatus?.scan_type || '').toLowerCase().includes('sast');
  const showResult = Boolean(latestScanId && (isSastScan || repoState !== 'idle'));
  const findings = findingRows(scanStatus);
  const findingCount = scanStatus?.total_vulnerabilities
    ?? scanStatus?.canonical_findings?.length
    ?? scanStatus?.findings?.length
    ?? 0;
  const stack = useMemo(() => scanStatus?.tech_stack || {}, [scanStatus?.tech_stack]);
  const languages = useMemo(() => languageRows(stack), [stack]);
  const topLanguage = languages[0] || null;
  const totalSourceFiles = stack.total_files || stack.file_count || stack.source_file_count || stack.scannable_files || 0;
  const downloadDisabled = !isCompleted || !latestScanId;
  const downloadTitle = downloadDisabled ? 'Repository scan must complete before downloads are available.' : 'Download repository scan artifact.';

  return (
    <div className="page-stack lab-page workflow-page repository-page">
      <WorkflowHero
        icon="source"
        eyebrow="Repository"
        title="Repository Scan"
        description="Run Semgrep, taint analysis, secrets, and dependency checks against authorized repositories."
        active="repository"
        onNavigate={onNavigate}
        actions={(
          <>
            {showResult && (
              <Button variant="secondary" disabled={downloadDisabled} title={downloadTitle} onClick={onDownloadPdf}>
                PDF
              </Button>
            )}
            <Button onClick={submitRepoScan} disabled={repoState === 'scanning' || isRunning}>
              {repoState === 'scanning' || isRunning ? 'Scanning' : 'Start Repository Scan'}
            </Button>
          </>
        )}
      />

      <div className="workflow-route-grid workflow-route-grid-repo">
        <section className="workflow-card workflow-card-command">
          <header>
            <h2>3. Repository Scan</h2>
            <p>Static analysis of source code.</p>
          </header>

          <div className="workflow-section">
            <h3>Repository</h3>
            <label className={repoForm.url ? 'field workflow-input-ok' : 'field'}>
              <span>Git Repository URL</span>
              <input value={repoForm.url} onChange={(event) => updateRepoForm('url', event.target.value)} placeholder="https://github.com/org/repo" />
              {repoForm.url && <span className="material-symbols-outlined">check</span>}
            </label>
            <div className="workflow-mini-grid">
              <label className="field">
                <span>Branch</span>
                <input value={repoForm.branch} onChange={(event) => updateRepoForm('branch', event.target.value)} />
              </label>
              <label className="field">
                <span>Access Token</span>
                <div className="input-with-action">
                  <input
                    type={showToken ? 'text' : 'password'}
                    autoComplete="off"
                    spellCheck={false}
                    value={repoForm.token}
                    onChange={(event) => updateRepoForm('token', event.target.value)}
                    placeholder="Optional token"
                  />
                  <button type="button" onClick={() => setShowToken((value) => !value)}>
                    {showToken ? 'Hide' : 'Show'}
                  </button>
                </div>
              </label>
            </div>
            <div className={repoForm.url ? 'workflow-success-banner' : 'workflow-warning-ack'}>
              <span className="material-symbols-outlined">{repoForm.url ? 'verified' : 'pending'}</span>
              <div>
                <strong>{repoForm.url ? 'Repository target configured' : 'Repository target pending'}</strong>
                <em>{repoLabel(repoForm.url)}</em>
              </div>
            </div>
          </div>

          <div className="workflow-section">
            <h3>SAST Engine</h3>
            <div className="workflow-mini-grid">
              <div className="workflow-meta"><span>Engine</span><strong>Semgrep</strong></div>
              <div className="workflow-meta"><span>Status</span><strong className={`repo-status repo-status-${statusTone(status)}`}>{status}</strong></div>
              <div className="workflow-meta"><span>Scan ID</span><strong>{latestScanId || '-'}</strong></div>
              <div className="workflow-meta"><span>Findings</span><strong>{formatNumber(findingCount)}</strong></div>
            </div>
          </div>

          <div className="workflow-section">
            <h3>Language Breakdown</h3>
            {languages.length ? (
              <div className="language-panel">
                <div className="language-donut dynamic" style={languageStyle(languages)}>
                  <strong>{`${Math.round(topLanguage?.percent || 0)}%`}</strong>
                  <span>{topLanguage?.name || 'Stack'}</span>
                </div>
                <div className="language-summary">
                  {languages.slice(0, 6).map((row, index) => (
                    <span key={row.rawName || row.name} title={row.count ? `${formatNumber(row.count)} source files` : undefined}>
                      <i className={`language-color-${index + 1}`} />
                      {row.name}
                      <em>{Number(row.percent || 0).toFixed(1)}%</em>
                    </span>
                  ))}
                  <small>{formatNumber(totalSourceFiles)} source files indexed</small>
                </div>
              </div>
            ) : (
              <EmptyState title="No repository stack yet" body="Run a repository scan to populate language and framework data." />
            )}
          </div>

          <Button onClick={submitRepoScan} disabled={!repoForm.url || repoState === 'scanning' || isRunning}>
            <span className="material-symbols-outlined">play_arrow</span>
            {repoState === 'scanning' || isRunning ? 'Scanning Repository' : 'Start Repository Scan'}
          </Button>
        </section>

        <section className="workflow-card workflow-card-support">
          <header>
            <h2>Repo Findings Preview</h2>
            <p>Results appear after the backend SAST scan completes.</p>
          </header>
          {findings.length ? (
            <div className="workflow-findings">
              {findings.map((finding, index) => (
                <button type="button" key={finding.finding_id || `${finding.title}-${index}`}>
                  <span className={`severity-chip severity-chip-${String(finding.severity || 'info').toLowerCase()}`}>{finding.severity || 'info'}</span>
                  <strong>{finding.title || finding.name || 'Finding'}</strong>
                  <code>{finding.file || finding.path || finding.target_url || '-'}</code>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState title="No repository findings yet" body="Findings will appear here once the scan reports real results." />
          )}
          <div className="repo-download-actions">
            <Button disabled={downloadDisabled} title={downloadTitle} onClick={onDownloadPdf}>Download PDF</Button>
            <Button variant="secondary" disabled={downloadDisabled} title={downloadTitle} onClick={onDownloadJson}>Download JSON</Button>
            <Button variant="ghost" onClick={onOpenReports}>Open Reports</Button>
          </div>
        </section>

        <div className="workflow-terminal-wrap">
          <TerminalPanel events={progressEvents} />
        </div>
      </div>
    </div>
  );
}
