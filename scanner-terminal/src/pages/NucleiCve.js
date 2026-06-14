import React from 'react';
import WorkflowHero from '../components/layout/WorkflowHero';
import Button from '../components/ui/Button';
import DataTable from '../components/ui/DataTable';
import EmptyState from '../components/ui/EmptyState';
import StatusPill from '../components/ui/StatusPill';

function countTargets(result) {
  return Array.isArray(result?.targets) ? result.targets.length : Number(result?.targets || 0);
}

function countFindings(result) {
  return Array.isArray(result?.findings)
    ? result.findings.length
    : Number(result?.findings || result?.raw_count || 0);
}

function policyOptionsFromStatus(status) {
  if (Array.isArray(status?.policy_options) && status.policy_options.length) {
    return status.policy_options;
  }
  return [
    { profile: 'safe', label: 'Safe', description: 'Non-intrusive default mode.' },
    { profile: 'professional', label: 'Professional', description: 'Broader authorized assessment mode.' },
    { profile: 'lab', label: 'Lab', description: 'Local labs and CTF targets only.' },
  ];
}

function formatNumber(value) {
  if (value === undefined || value === null || value === '') return '0';
  return Number(value).toLocaleString();
}

function percent(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return '0.000';
  return number.toFixed(3);
}

function parseList(value) {
  return String(value || '')
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function severityMatrix(records, nucleiResult) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const sources = [
    ...(Array.isArray(records) ? records : []),
    ...(Array.isArray(nucleiResult?.findings) ? nucleiResult.findings : []),
  ];
  sources.forEach((item) => {
    const severity = String(item.nvd_severity || item.severity || 'info').toLowerCase();
    if (counts[severity] !== undefined) counts[severity] += 1;
    else counts.info += 1;
  });
  return counts;
}

export default function NucleiCve({
  latestScanId,
  scanStatus,
  nucleiConfig,
  nucleiState,
  nucleiResult,
  nucleiAssetState,
  nucleiAssetStatus,
  templateTrustState,
  templateTrustConfig,
  cveIntelState,
  cveIntelResult,
  updateNucleiConfig,
  updateTemplateTrustConfig,
  runNucleiIntegration,
  loadNucleiStatus,
  loadTemplateTrust,
  saveTemplateTrust,
  installNucleiEngine,
  updateNucleiTemplates,
  enrichCveIntel,
  onNavigate,
}) {
  const engineReady = Boolean(nucleiAssetStatus?.ok || nucleiAssetStatus?.binary_path);
  const templateCount = nucleiAssetStatus?.metadata?.template_count || nucleiAssetStatus?.template_count || 0;
  const nucleiTargets = countTargets(nucleiResult);
  const nucleiFindings = countFindings(nucleiResult);
  const nucleiErrors = Array.isArray(nucleiResult?.errors) ? nucleiResult.errors : [];
  const records = Array.isArray(cveIntelResult?.records) ? cveIntelResult.records : [];
  const policyOptions = policyOptionsFromStatus(nucleiAssetStatus);
  const activePolicy = policyOptions.find((option) => option.profile === nucleiConfig?.policyProfile) || policyOptions[0];
  const severities = severityMatrix(records, nucleiResult);
  const configuredSeverities = parseList(nucleiConfig?.severity);
  const configuredTags = parseList(nucleiConfig?.tags);
  const excludedTags = parseList(nucleiConfig?.excludeTags);

  const cveColumns = [
    { key: 'cve_id', label: 'CVE', width: '140px' },
    {
      key: 'nvd_severity',
      label: 'Severity',
      width: '110px',
      render: (row) => String(row.nvd_severity || 'unknown').toUpperCase(),
    },
    {
      key: 'cvss_score',
      label: 'CVSS',
      width: '80px',
      render: (row) => row.cvss_score || '0.0',
    },
    {
      key: 'epss_score',
      label: 'EPSS',
      width: '90px',
      render: (row) => percent(row.epss_score),
    },
    {
      key: 'cisa_kev',
      label: 'KEV',
      width: '80px',
      render: (row) => (row.cisa_kev ? 'yes' : 'no'),
    },
    {
      key: 'priority_score',
      label: 'Priority',
      width: '100px',
      render: (row) => formatNumber(row.priority_score),
    },
    {
      key: 'description',
      label: 'Description',
      render: (row) => row.description || row.cisa_required_action || 'No public description loaded yet.',
    },
  ];

  return (
    <div className="page-stack lab-page workflow-page nuclei-page">
      <WorkflowHero
        icon="hub"
        eyebrow="Template Coverage"
        title="Nuclei & CVE Intelligence"
        description="Manage Nuclei assets, run template coverage, and enrich CVE-backed findings."
        active="nuclei"
        onNavigate={onNavigate}
        actions={(
          <>
            <Button variant="secondary" onClick={loadNucleiStatus}>Refresh</Button>
            <Button onClick={runNucleiIntegration} disabled={!latestScanId || !engineReady || nucleiState === 'running'}>
              {nucleiState === 'running' ? 'Running' : 'Run Nuclei'}
            </Button>
          </>
        )}
      />

      <div className="workflow-route-grid workflow-route-grid-nuclei">
        <section className="workflow-card workflow-card-command">
          <header>
            <h2>4. Nuclei & CVE</h2>
            <p>Template scanning and CVE enrichment.</p>
          </header>

          <div className="workflow-section">
            <h3>Nuclei Engine</h3>
            <div className="workflow-mini-grid">
              <div className="workflow-meta"><span>Engine</span><strong>{engineReady ? 'ready' : nucleiAssetState}</strong></div>
              <div className="workflow-meta"><span>Version</span><strong>{nucleiAssetStatus?.version || nucleiAssetStatus?.metadata?.version || '-'}</strong></div>
              <div className="workflow-meta"><span>Templates</span><strong>{formatNumber(templateCount)}</strong></div>
              <div className="workflow-meta"><span>Active Scan</span><strong>{latestScanId || 'none'}</strong></div>
            </div>
            <div className="engine-strip">
              <Button variant="secondary" onClick={installNucleiEngine} disabled={nucleiAssetState === 'installing' || nucleiAssetState === 'updating'}>
                {nucleiAssetState === 'installing' ? 'Installing' : 'Install Engine'}
              </Button>
              <Button variant="secondary" onClick={updateNucleiTemplates} disabled={!engineReady || nucleiAssetState === 'installing' || nucleiAssetState === 'updating'}>
                {nucleiAssetState === 'updating' ? 'Updating' : 'Update Templates'}
              </Button>
              <Button variant="secondary" onClick={loadTemplateTrust}>Reload Policy</Button>
            </div>
          </div>

          <div className="workflow-section">
            <h3>Template Policy</h3>
            <label className="field">
              <span>Policy</span>
              <select value={nucleiConfig?.policyProfile || 'safe'} onChange={(event) => updateNucleiConfig('policyProfile', event.target.value)}>
                {policyOptions.map((option) => (
                  <option key={option.profile} value={option.profile}>
                    {option.label || option.profile}
                  </option>
                ))}
              </select>
            </label>
            <div className="workflow-mini-grid">
              <label className="field">
                <span>Severity</span>
                <input value={nucleiConfig?.severity || ''} onChange={(event) => updateNucleiConfig('severity', event.target.value)} />
              </label>
              <label className="field">
                <span>Rate Limit</span>
                <input type="number" min="1" value={nucleiConfig?.rateLimit || ''} onChange={(event) => updateNucleiConfig('rateLimit', event.target.value)} />
              </label>
            </div>
            <div className="tag-row">
              {(configuredSeverities.length ? configuredSeverities : ['all severities']).map((item) => <span key={item}>{item}</span>)}
            </div>
            {configuredTags.length > 0 && (
              <div className="tag-row">
                {configuredTags.map((item) => <span key={item}>{item}</span>)}
              </div>
            )}
            {excludedTags.length > 0 && (
              <div className="tag-row danger">
                {excludedTags.map((item) => <span key={item}>{item}</span>)}
              </div>
            )}
            <div className="workflow-warning-ack">
              <span className="material-symbols-outlined">warning</span>
              <span>{activePolicy?.description || 'Nuclei policy controls template tag exclusions.'}</span>
            </div>
            {nucleiConfig?.policyProfile !== 'safe' && (
              <label className="workflow-warning-ack">
                <input
                  type="checkbox"
                  checked={Boolean(nucleiConfig?.policyAcknowledged)}
                  onChange={(event) => updateNucleiConfig('policyAcknowledged', event.target.checked)}
                />
                <span>I confirm this is an authorized professional test scope.</span>
              </label>
            )}
          </div>

          <div className="workflow-section">
            <h3>CVE Enrichment</h3>
            <div className="workflow-mini-grid">
              <div className="workflow-meta"><span>Records</span><strong>{formatNumber(cveIntelResult?.cve_count || records.length)}</strong></div>
              <div className="workflow-meta"><span>KEV</span><strong>{formatNumber(cveIntelResult?.kev_count || 0)}</strong></div>
              <div className="workflow-meta"><span>Targets</span><strong>{formatNumber(nucleiTargets)}</strong></div>
              <div className="workflow-meta"><span>Matches</span><strong>{formatNumber(nucleiResult?.raw_count || 0)}</strong></div>
              <div className="workflow-meta"><span>Imported</span><strong>{formatNumber(nucleiFindings)}</strong></div>
            </div>
            <Button variant="secondary" onClick={enrichCveIntel} disabled={!latestScanId || cveIntelState === 'running'}>
              {cveIntelState === 'running' ? 'Enriching CVEs' : 'Enrich CVEs'}
            </Button>
          </div>
        </section>

        <section className="workflow-card workflow-card-support">
          <header>
            <h2>Severity Matrix</h2>
            <p>Populated from real Nuclei findings and CVE enrichment records.</p>
          </header>
          <div className="workflow-severity-matrix">
            {Object.entries(severities).map(([severity, count]) => (
              <div key={severity}>
                <span>{severity}</span>
                <strong className={`severity-text-${severity}`}>{formatNumber(count)}</strong>
              </div>
            ))}
          </div>

          <div className="workflow-section">
            <h3>Managed Assets</h3>
            <div className="nuclei-asset-card">
              <div>
                <span>Binary Path</span>
                <code>{nucleiAssetStatus?.binary_path || nucleiAssetStatus?.metadata?.managed_binary || 'Not installed yet'}</code>
              </div>
              <div>
                <span>Template Directory</span>
                <code>{nucleiAssetStatus?.template_dir || 'Managed template directory pending'}</code>
              </div>
            </div>
          </div>

          <div className="workflow-section">
            <h3>Trust Policy</h3>
            <div className="workflow-mini-grid">
              <label className="field">
                <span>Allowed Tags</span>
                <input value={templateTrustConfig?.allowed_tags || ''} onChange={(event) => updateTemplateTrustConfig('allowed_tags', event.target.value)} placeholder="Optional allowlist" />
              </label>
              <label className="field">
                <span>Denied Tags</span>
                <input value={templateTrustConfig?.denied_tags || ''} onChange={(event) => updateTemplateTrustConfig('denied_tags', event.target.value)} placeholder="bruteforce, destructive, dos" />
              </label>
            </div>
            <label className="field">
              <span>Trusted Sources</span>
              <input value={templateTrustConfig?.trusted_sources || ''} onChange={(event) => updateTemplateTrustConfig('trusted_sources', event.target.value)} />
            </label>
            <Button variant="secondary" onClick={saveTemplateTrust} disabled={templateTrustState === 'saving'}>
              {templateTrustState === 'saving' ? 'Saving Policy' : 'Save Trust Policy'}
            </Button>
          </div>

          {(nucleiErrors.length > 0 || cveIntelResult?.errors?.length > 0) && (
            <div className="nuclei-errors">
              {nucleiErrors.map((error, index) => <code key={`nuclei-${index}`}>{error}</code>)}
              {(cveIntelResult?.errors || []).map((error, index) => <code key={`cve-${index}`}>{error}</code>)}
            </div>
          )}
        </section>

        <section className="workflow-card workflow-card-wide">
          <header>
            <h2>CVE Records</h2>
            <p>Enriched public risk context for the active scan.</p>
            <StatusPill status={cveIntelState} />
          </header>
          {records.length ? (
            <DataTable columns={cveColumns} rows={records} rowKey="cve_id" emptyTitle="No enriched CVE records yet" />
          ) : (
            <EmptyState title={latestScanId ? 'No enriched CVE records yet' : 'Run or select a scan first'} body="CVE records appear after backend enrichment returns data." />
          )}
        </section>
      </div>
    </div>
  );
}
