import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import DataTable from '../components/ui/DataTable';
import MetricCard from '../components/ui/MetricCard';
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

export default function NucleiCve({
  latestScanId,
  scanStatus,
  nucleiConfig,
  nucleiState,
  nucleiResult,
  nucleiAssetState,
  nucleiAssetStatus,
  cveIntelState,
  cveIntelResult,
  updateNucleiConfig,
  runNucleiIntegration,
  loadNucleiStatus,
  installNucleiEngine,
  updateNucleiTemplates,
  enrichCveIntel,
  onNavigate,
}) {
  const engineReady = Boolean(nucleiAssetStatus?.ok || nucleiAssetStatus?.binary_path);
  const templateCount = nucleiAssetStatus?.metadata?.template_count || 0;
  const nucleiTargets = countTargets(nucleiResult);
  const nucleiFindings = countFindings(nucleiResult);
  const nucleiErrors = Array.isArray(nucleiResult?.errors) ? nucleiResult.errors : [];
  const records = Array.isArray(cveIntelResult?.records) ? cveIntelResult.records : [];
  const policyOptions = policyOptionsFromStatus(nucleiAssetStatus);
  const activePolicy = policyOptions.find((option) => option.profile === nucleiConfig?.policyProfile) || policyOptions[0];

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
    <div className="page-stack nuclei-page">
      <PageHeader
        eyebrow="Template Coverage"
        title="Nuclei & CVE Intelligence"
        description="Manage Nuclei assets, run template coverage against the active Wraith corpus, and enrich CVE-backed findings with public risk context."
        actions={(
          <>
            <Button variant="secondary" onClick={() => onNavigate('automated-workspace')}>Workspace</Button>
            <Button onClick={runNucleiIntegration} disabled={!latestScanId || !engineReady || nucleiState === 'running'}>
              {nucleiState === 'running' ? 'Running...' : 'Run Nuclei'}
            </Button>
          </>
        )}
      />

      <div className="metric-grid five">
        <MetricCard label="Active Scan" value={latestScanId || 'none'} detail={scanStatus?.status || 'idle'} />
        <MetricCard label="Targets" value={nucleiTargets} detail="Nuclei input set" tone="blue" />
        <MetricCard label="Matches" value={nucleiResult?.raw_count || 0} detail="raw JSONL matches" tone="amber" />
        <MetricCard label="Imported" value={nucleiFindings} detail="Wraith findings" tone="emerald" />
        <MetricCard label="CVEs" value={cveIntelResult?.cve_count || 0} detail={`${cveIntelResult?.kev_count || 0} KEV`} tone="red" />
      </div>

      <div className="nuclei-page-grid">
        <Card
          title="Managed Assets"
          eyebrow="Engine"
          actions={<Button variant="ghost" onClick={loadNucleiStatus}>Refresh</Button>}
        >
          <div className="nuclei-result-strip">
            <div>
              <span>Engine</span>
              <strong>{engineReady ? 'ready' : nucleiAssetState}</strong>
            </div>
            <div>
              <span>Templates</span>
              <strong>{formatNumber(templateCount)}</strong>
            </div>
            <div>
              <span>Asset State</span>
              <strong>{nucleiAssetState}</strong>
            </div>
            <div>
              <span>Policy</span>
              <strong>{nucleiConfig?.policyProfile || 'safe'}</strong>
            </div>
          </div>
          <div className="nuclei-asset-card">
            <div>
              <span>Binary Path</span>
              <code>{nucleiAssetStatus?.binary_path || nucleiAssetStatus?.metadata?.managed_binary || 'Not installed yet'}</code>
            </div>
            <div>
              <span>Template Directory</span>
              <code>{nucleiAssetStatus?.template_dir || 'Managed template directory pending'}</code>
            </div>
            <div className="nuclei-asset-actions split">
              <Button
                variant="secondary"
                onClick={installNucleiEngine}
                disabled={nucleiAssetState === 'installing' || nucleiAssetState === 'updating'}
              >
                {nucleiAssetState === 'installing' ? 'Installing...' : 'Install / Update Engine'}
              </Button>
              <Button
                variant="secondary"
                onClick={updateNucleiTemplates}
                disabled={!engineReady || nucleiAssetState === 'installing' || nucleiAssetState === 'updating'}
              >
                {nucleiAssetState === 'updating' ? 'Updating...' : 'Update Templates'}
              </Button>
            </div>
          </div>
          <div className="nuclei-note">
            <span className="material-symbols-outlined">verified_user</span>
            <p>
              Managed installs keep Wraith desktop/web users away from terminal setup while preserving explicit policy controls.
            </p>
          </div>
        </Card>

        <Card title="Run Configuration" eyebrow="Policy">
          <div className="nuclei-form">
            <label className="field wide">
              <span>Targets</span>
              <textarea
                value={nucleiConfig?.targets || ''}
                onChange={(event) => updateNucleiConfig('targets', event.target.value)}
                placeholder="Leave empty to use active scan target and corpus URLs."
              />
            </label>
            <label className="field wide">
              <span>Template Paths</span>
              <textarea
                value={nucleiConfig?.templates || ''}
                onChange={(event) => updateNucleiConfig('templates', event.target.value)}
                placeholder="Optional managed or private template paths, separated by commas or new lines."
              />
            </label>
            <div className="form-grid compact">
              <label className="field">
                <span>Severity</span>
                <input value={nucleiConfig?.severity || ''} onChange={(event) => updateNucleiConfig('severity', event.target.value)} />
              </label>
              <label className="field">
                <span>Tags</span>
                <input value={nucleiConfig?.tags || ''} onChange={(event) => updateNucleiConfig('tags', event.target.value)} placeholder="Optional" />
              </label>
              <label className="field">
                <span>Exclude Tags</span>
                <input value={nucleiConfig?.excludeTags || ''} onChange={(event) => updateNucleiConfig('excludeTags', event.target.value)} placeholder="Extra exclusions" />
              </label>
              <label className="field">
                <span>Rate Limit</span>
                <input type="number" min="1" value={nucleiConfig?.rateLimit || ''} onChange={(event) => updateNucleiConfig('rateLimit', event.target.value)} />
              </label>
              <label className="field">
                <span>HTTP Timeout</span>
                <input type="number" min="1" value={nucleiConfig?.timeout || ''} onChange={(event) => updateNucleiConfig('timeout', event.target.value)} />
              </label>
              <label className="field">
                <span>Process Timeout</span>
                <input type="number" min="10" value={nucleiConfig?.processTimeout || ''} onChange={(event) => updateNucleiConfig('processTimeout', event.target.value)} />
              </label>
            </div>
            <label className="check-row nuclei-safety">
              <span>Policy Profile</span>
              <select
                value={nucleiConfig?.policyProfile || 'safe'}
                onChange={(event) => updateNucleiConfig('policyProfile', event.target.value)}
              >
                {policyOptions.map((option) => (
                  <option key={option.profile} value={option.profile}>
                    {option.label || option.profile}
                  </option>
                ))}
              </select>
            </label>
            <div className="nuclei-policy-note">
              <strong>{activePolicy?.label || activePolicy?.profile || 'Safe'} mode</strong>
              <p>{activePolicy?.description || 'Nuclei policy controls template tag exclusions.'}</p>
              {activePolicy?.default_exclude_tags?.length > 0 && (
                <code>Default excludes: {activePolicy.default_exclude_tags.join(', ')}</code>
              )}
            </div>
            {nucleiConfig?.policyProfile !== 'safe' && (
              <label className="check-row nuclei-safety nuclei-ack">
                <input
                  type="checkbox"
                  checked={Boolean(nucleiConfig?.policyAcknowledged)}
                  onChange={(event) => updateNucleiConfig('policyAcknowledged', event.target.checked)}
                />
                <span>I confirm this is an authorized professional test scope.</span>
              </label>
            )}
          </div>
        </Card>

        <Card
          title="CVE Intelligence"
          eyebrow="NVD EPSS KEV"
          className="dashboard-wide"
          actions={(
            <Button variant="secondary" onClick={enrichCveIntel} disabled={!latestScanId || cveIntelState === 'running'}>
              {cveIntelState === 'running' ? 'Enriching...' : 'Enrich CVEs'}
            </Button>
          )}
        >
          <div className="nuclei-intel-header">
            <StatusPill status={cveIntelState} />
            <span>{cveIntelResult?.updated_findings || 0} findings updated</span>
            <span>{cveIntelResult?.kev_count || 0} CISA KEV matches</span>
          </div>
          <DataTable
            columns={cveColumns}
            rows={records}
            rowKey="cve_id"
            emptyTitle={latestScanId ? 'No enriched CVE records yet' : 'Run or select a scan first'}
          />
        </Card>

        {(nucleiErrors.length > 0 || cveIntelResult?.errors?.length > 0) && (
          <Card title="Integration Errors" eyebrow="Diagnostics" className="dashboard-wide">
            <div className="nuclei-errors">
              {nucleiErrors.map((error, index) => (
                <code key={`nuclei-${index}`}>{error}</code>
              ))}
              {(cveIntelResult?.errors || []).map((error, index) => (
                <code key={`cve-${index}`}>{error}</code>
              ))}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
