import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import MetricCard from '../components/ui/MetricCard';
import TerminalPanel from '../components/ui/TerminalPanel';
import ScanStatusStrip from '../components/scanner/ScanStatusStrip';
import ScanTimeline from '../components/scanner/ScanTimeline';
import SeveritySummary from '../components/scanner/SeveritySummary';

export default function AutomatedWorkspace({
  scanStatus,
  latestScanId,
  dashboard,
  progressEvents,
  corpusRequests,
  nucleiConfig,
  nucleiState,
  nucleiResult,
  nucleiAssetState,
  nucleiAssetStatus,
  updateNucleiConfig,
  runNucleiIntegration,
  loadNucleiStatus,
  installNucleiEngine,
  updateNucleiTemplates,
  refreshStatus,
  submitScan,
  onNavigate,
}) {
  const counts = dashboard?.severityCounts || {};
  const nucleiTargets = Array.isArray(nucleiResult?.targets)
    ? nucleiResult.targets.length
    : Number(nucleiResult?.targets || 0);
  const nucleiFindings = Array.isArray(nucleiResult?.findings)
    ? nucleiResult.findings.length
    : Number(nucleiResult?.findings || nucleiResult?.raw_count || 0);
  const nucleiErrors = Array.isArray(nucleiResult?.errors) ? nucleiResult.errors : [];
  const templateCount = nucleiAssetStatus?.metadata?.template_count || 0;
  const engineReady = Boolean(nucleiAssetStatus?.ok || nucleiAssetStatus?.binary_path);
  const policyOptions = Array.isArray(nucleiAssetStatus?.policy_options)
    ? nucleiAssetStatus.policy_options
    : [
        { profile: 'safe', label: 'Safe', description: 'Non-intrusive default mode.' },
        { profile: 'professional', label: 'Professional', description: 'Broader authorized assessment mode.' },
        { profile: 'lab', label: 'Lab', description: 'Local labs and CTF targets only.' },
      ];
  const activePolicy = policyOptions.find((option) => option.profile === nucleiConfig?.policyProfile) || policyOptions[0];
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Automated Workspace"
        title={scanStatus?.url || scanStatus?.target || 'Risk Dashboard'}
        description="Live scan status, attack surface, findings, evidence, and report actions."
        actions={(
          <>
            <Button variant="secondary" onClick={refreshStatus} disabled={!latestScanId}>Refresh</Button>
            <Button onClick={submitScan}>Scan again</Button>
          </>
        )}
      />
      <ScanStatusStrip
        scanId={latestScanId}
        status={scanStatus?.status || 'idle'}
        requests={corpusRequests.length}
        findings={dashboard?.totalFindings || 0}
        imports={dashboard?.importCount || 0}
      />
      <div className="workspace-tabs">
        <button onClick={() => onNavigate('automated-workspace')}>Overview</button>
        <button onClick={() => onNavigate('findings')}>Findings</button>
        <button onClick={() => onNavigate('evidence')}>Scanned URLs</button>
        <button onClick={() => onNavigate('automated-setup')}>Scan details</button>
        <button onClick={() => onNavigate('reports')}>Reporting & logs</button>
      </div>
      <div className="metric-grid">
        <MetricCard label="Total Findings" value={dashboard?.totalFindings || 0} tone="red" />
        <MetricCard label="Confirmed" value={dashboard?.confirmed || 0} tone="emerald" />
        <MetricCard label="Requests" value={corpusRequests.length} tone="cyan" />
        <MetricCard label="Imports" value={dashboard?.importCount || 0} tone="amber" />
      </div>
      <div className="dashboard-grid">
        <Card title="Severity Summary" eyebrow="Risk">
          <SeveritySummary counts={counts} />
        </Card>
        <Card title="Execution Pipeline" eyebrow="Run State">
          <div className="pipeline">
            <span className="complete">Discovery</span>
            <span className="active">Fuzzing</span>
            <span>Proofing</span>
            <span>Reporting</span>
          </div>
        </Card>
        <ScanTimeline events={progressEvents} />
        <Card
          title="Nuclei Coverage"
          eyebrow="CVE Templates"
          className="dashboard-wide nuclei-card"
          actions={(
            <>
              <Button variant="ghost" onClick={loadNucleiStatus}>Status</Button>
              <Button
                variant="secondary"
                onClick={runNucleiIntegration}
                disabled={!latestScanId || nucleiState === 'running' || !engineReady}
              >
                {nucleiState === 'running' ? 'Running...' : 'Run Nuclei'}
              </Button>
            </>
          )}
        >
          <div className="nuclei-layout">
            <div className="nuclei-form">
              <label className="field wide">
                <span>Targets</span>
                <textarea
                  value={nucleiConfig?.targets || ''}
                  onChange={(event) => updateNucleiConfig('targets', event.target.value)}
                  placeholder="Optional. Leave empty to use scanned URLs from the corpus."
                />
              </label>
              <label className="field wide">
                <span>Template Paths</span>
                <textarea
                  value={nucleiConfig?.templates || ''}
                  onChange={(event) => updateNucleiConfig('templates', event.target.value)}
                  placeholder="Optional local template directories or files, separated by commas or new lines."
                />
              </label>
              <div className="form-grid compact">
                <label className="field">
                  <span>Severity</span>
                  <input
                    value={nucleiConfig?.severity || ''}
                    onChange={(event) => updateNucleiConfig('severity', event.target.value)}
                  />
                </label>
                <label className="field">
                  <span>Tags</span>
                  <input
                    value={nucleiConfig?.tags || ''}
                    onChange={(event) => updateNucleiConfig('tags', event.target.value)}
                    placeholder="Optional"
                  />
                </label>
                <label className="field">
                  <span>Exclude Tags</span>
                  <input
                    value={nucleiConfig?.excludeTags || ''}
                    onChange={(event) => updateNucleiConfig('excludeTags', event.target.value)}
                    placeholder="Extra exclusions"
                  />
                </label>
                <label className="field">
                  <span>Rate Limit</span>
                  <input
                    value={nucleiConfig?.rateLimit || ''}
                    onChange={(event) => updateNucleiConfig('rateLimit', event.target.value)}
                    type="number"
                    min="1"
                  />
                </label>
                <label className="field">
                  <span>HTTP Timeout</span>
                  <input
                    value={nucleiConfig?.timeout || ''}
                    onChange={(event) => updateNucleiConfig('timeout', event.target.value)}
                    type="number"
                    min="1"
                  />
                </label>
                <label className="field">
                  <span>Process Timeout</span>
                  <input
                    value={nucleiConfig?.processTimeout || ''}
                    onChange={(event) => updateNucleiConfig('processTimeout', event.target.value)}
                    type="number"
                    min="10"
                  />
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
                <strong>{activePolicy?.label || 'Safe'} mode</strong>
                <p>{activePolicy?.description || 'Nuclei policy controls template tag exclusions.'}</p>
                {activePolicy?.default_exclude_tags?.length > 0 && (
                  <code>Excludes: {activePolicy.default_exclude_tags.join(', ')}</code>
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
            <div className="nuclei-summary">
              <div className="nuclei-asset-card">
                <div>
                  <span>Managed Engine</span>
                  <strong>{engineReady ? 'Ready' : 'Missing'}</strong>
                  <code>{nucleiAssetStatus?.binary_path || nucleiAssetStatus?.metadata?.managed_binary || 'Not installed yet'}</code>
                </div>
                <div>
                  <span>Templates</span>
                  <strong>{templateCount}</strong>
                  <code>{nucleiAssetStatus?.template_dir || 'Managed template directory pending'}</code>
                </div>
                <div className="nuclei-asset-actions">
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
              <div className="nuclei-result-strip">
                <div>
                  <span>State</span>
                  <strong>{nucleiState}</strong>
                </div>
                <div>
                  <span>Targets</span>
                  <strong>{nucleiTargets}</strong>
                </div>
                <div>
                  <span>Matches</span>
                  <strong>{nucleiResult?.raw_count || 0}</strong>
                </div>
                <div>
                  <span>Imported</span>
                  <strong>{nucleiFindings}</strong>
                </div>
              </div>
              <div className="nuclei-note">
                <span className="material-symbols-outlined">shield_lock</span>
                <p>
                  Safe mode excludes brute force, DoS, fuzzing, RCE, intrusive,
                  and destructive template tags unless explicitly enabled.
                </p>
              </div>
              {nucleiErrors.length > 0 && (
                <div className="nuclei-errors">
                  {nucleiErrors.map((error, index) => (
                    <code key={`${error}-${index}`}>{error}</code>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Card>
        <TerminalPanel events={progressEvents} />
      </div>
    </div>
  );
}
