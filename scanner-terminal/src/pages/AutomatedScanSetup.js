import React, { useMemo, useState } from 'react';
import WorkflowHero from '../components/layout/WorkflowHero';
import Button from '../components/ui/Button';

const PRIVATE_IPV4_PATTERNS = [
  /^127\./,
  /^10\./,
  /^169\.254\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^0\./,
];

function validateTarget(value, safetyMode) {
  const target = String(value || '').trim();
  if (!target) return 'Enter the authorized base URL you want to scan.';
  try {
    const parsed = new URL(target);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return 'Use an http:// or https:// URL.';
    }
    const host = parsed.hostname.toLowerCase();
    const privateHost = host === 'localhost'
      || host.endsWith('.localhost')
      || PRIVATE_IPV4_PATTERNS.some((pattern) => pattern.test(host));
    if (privateHost && safetyMode !== 'lab') {
      return 'Local/private targets require Lab safety mode.';
    }
  } catch (_error) {
    return 'Enter a valid absolute URL.';
  }
  return '';
}

function parseItems(value) {
  return String(value || '')
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function importRows(form) {
  return [
    ['openapiImports', 'description', 'OpenAPI', form.openapiImports],
    ['postmanImports', 'folder_open', 'Postman', form.postmanImports],
    ['harImports', 'language', 'HAR', form.harImports],
    ['graphqlImports', 'hub', 'GraphQL', form.graphqlImports],
  ];
}

function importCount(form) {
  return [
    form.openapiImports,
    form.postmanImports,
    form.harImports,
    form.graphqlImports,
    form.sequenceWorkflows,
  ].reduce((total, value) => total + parseItems(value).length, 0);
}

export default function AutomatedScanSetup({
  form,
  updateForm,
  submitScan,
  launchState,
  launchError,
  latestScanId,
  onNavigate,
}) {
  const [showBearerToken, setShowBearerToken] = useState(false);
  const targetError = useMemo(
    () => validateTarget(form.targetUrl, form.safetyMode),
    [form.safetyMode, form.targetUrl],
  );
  const isLaunching = launchState === 'starting';
  const canLaunch = !isLaunching && !targetError;
  const imports = importCount(form);
  const workflows = parseItems(form.sequenceWorkflows);

  return (
    <div className="page-stack lab-page workflow-page scan-setup-page">
      <WorkflowHero
        icon="radar"
        eyebrow="Automated"
        title="Automated Workflow"
        description="Configure the target, authorization, API context, and workflow inputs for the next scan."
        active="automated-setup"
        onNavigate={onNavigate}
        actions={(
          <Button onClick={submitScan} disabled={!canLaunch} title={targetError || ''}>
            {isLaunching ? 'Launching' : 'Launch Scan'}
          </Button>
        )}
      />

      <div className="workflow-route-grid workflow-route-grid-setup">
        <section className="workflow-card workflow-card-command">
          <header>
            <h2>1. Scan Setup</h2>
            <p>Configure your mission.</p>
          </header>

          <div className="workflow-form">
            <div className="workflow-section">
              <h3>Target</h3>
              <label className={targetError ? 'field' : 'field workflow-input-ok'}>
                <span>Target URL</span>
                <input
                  value={form.targetUrl}
                  onChange={(event) => updateForm('targetUrl', event.target.value)}
                  placeholder="https://your-authorized-target.com"
                  aria-invalid={Boolean(targetError)}
                />
                {!targetError && <span className="material-symbols-outlined">check</span>}
                <em className={targetError ? 'field-error' : 'field-hint'}>
                  {targetError || 'Authorized http:// or https:// target ready.'}
                </em>
              </label>

              <div className="workflow-mini-grid">
                <label className="field">
                  <span>Scope</span>
                  <select value={form.safetyMode} onChange={(event) => updateForm('safetyMode', event.target.value)}>
                    <option value="safe">safe</option>
                    <option value="intrusive">intrusive</option>
                    <option value="lab">lab</option>
                  </select>
                </label>
                <label className="field">
                  <span>Depth</span>
                  <input type="number" min="1" max="8" value={form.depth} onChange={(event) => updateForm('depth', event.target.value)} />
                </label>
              </div>

              <div className="workflow-kpi-row">
                <div className="workflow-mini-stat"><span>Depth</span><strong>{form.depth || '-'}</strong></div>
                <div className="workflow-mini-stat"><span>Rate</span><strong>backend</strong></div>
                <div className="workflow-mini-stat"><span>Timeout</span><strong>{form.timeout || '-'}s</strong></div>
              </div>
            </div>

            <div className="workflow-section">
              <h3>Authentication</h3>
              <div className="workflow-mini-grid">
                <label className="field">
                  <span>Auth Type</span>
                  <select value={form.authType} onChange={(event) => updateForm('authType', event.target.value)}>
                    <option value="anonymous">anonymous</option>
                    <option value="bearer">bearer</option>
                    <option value="header">header</option>
                    <option value="cookie">cookie</option>
                    <option value="playwright_storage">playwright_storage</option>
                  </select>
                </label>
                <label className="field">
                  <span>Role</span>
                  <input value={form.authRole} onChange={(event) => updateForm('authRole', event.target.value)} />
                </label>
              </div>
              <label className="field">
                <span>Token / Secret</span>
                <div className="input-with-action">
                  <input
                    type={showBearerToken ? 'text' : 'password'}
                    autoComplete="off"
                    spellCheck={false}
                    value={form.bearerToken}
                    onChange={(event) => updateForm('bearerToken', event.target.value)}
                    placeholder="Optional token"
                  />
                  <button type="button" onClick={() => setShowBearerToken((value) => !value)}>
                    {showBearerToken ? 'Hide' : 'Show'}
                  </button>
                </div>
              </label>
              <div className="workflow-mini-grid">
                <label className="field">
                  <span>Health URL</span>
                  <input value={form.healthUrl} onChange={(event) => updateForm('healthUrl', event.target.value)} placeholder="Optional health check" />
                </label>
                <label className="field">
                  <span>Expected Text</span>
                  <input value={form.healthText} onChange={(event) => updateForm('healthText', event.target.value)} placeholder="Optional marker" />
                </label>
              </div>
              <label className="field">
                <span>Storage State Path</span>
                <input value={form.storageStatePath} onChange={(event) => updateForm('storageStatePath', event.target.value)} placeholder="Optional Playwright storage state file" />
              </label>
            </div>

            <div className="workflow-section">
              <h3>Imports</h3>
              {importRows(form).map(([field, icon, label, value]) => (
                <label className={parseItems(value).length ? 'workflow-import-row active' : 'workflow-import-row'} key={field}>
                  <span className="material-symbols-outlined">{icon}</span>
                  <strong>{label}</strong>
                  <input value={value} onChange={(event) => updateForm(field, event.target.value)} placeholder="Optional file path or URL" />
                  <em>{parseItems(value).length ? `${parseItems(value).length} loaded` : 'empty'}</em>
                </label>
              ))}
              <label className="field">
                <span>GraphQL Endpoint</span>
                <input value={form.graphqlEndpoint} onChange={(event) => updateForm('graphqlEndpoint', event.target.value)} placeholder="Optional endpoint override" />
              </label>
            </div>

            <div className="workflow-section">
              <h3>Sequence Workflows</h3>
              <label className={workflows.length ? 'toggle-row active' : 'toggle-row'}>
                <span className="material-symbols-outlined">account_tree</span>
                <strong>Stateful workflow files</strong>
                <em>{workflows.length ? `${workflows.length} loaded` : 'Optional'}</em>
              </label>
              <textarea
                value={form.sequenceWorkflows}
                onChange={(event) => updateForm('sequenceWorkflows', event.target.value)}
                placeholder="Optional workflow file paths, separated by commas or new lines."
              />
            </div>

            <Button onClick={submitScan} disabled={!canLaunch} title={targetError || ''}>
              <span className="material-symbols-outlined">play_arrow</span>
              {isLaunching ? 'Launching Scan' : 'Launch Scan'}
            </Button>
          </div>
        </section>

        <aside className="workflow-card workflow-card-support">
          <header>
            <h2>Ready Check</h2>
            <p>Only real scan data appears after launch.</p>
          </header>
          <div className="workflow-scan-meta">
            <div className="workflow-meta"><span>Target</span><strong>{form.targetUrl || 'not set'}</strong></div>
            <div className="workflow-meta"><span>Auth</span><strong>{form.authType || 'anonymous'}</strong></div>
            <div className="workflow-meta"><span>Imports</span><strong>{imports}</strong></div>
            <div className="workflow-meta"><span>Validation</span><strong className={targetError ? 'tone-danger' : 'tone-success'}>{targetError ? 'blocked' : 'ready'}</strong></div>
          </div>
          {targetError ? (
            <div className="workflow-warning-ack">
              <span className="material-symbols-outlined">warning</span>
              <span>{targetError}</span>
            </div>
          ) : launchError ? (
            <div className="workflow-warning-ack">
              <span className="material-symbols-outlined">error</span>
              <span>{launchError}</span>
            </div>
          ) : (
            <div className="workflow-success-banner">
              <span className="material-symbols-outlined">verified</span>
              <div>
                <strong>Setup ready</strong>
                <em>Launch creates a backend scan and unlocks Cockpit.</em>
              </div>
            </div>
          )}
          <div className="button-column">
            <Button
              variant="secondary"
              onClick={() => onNavigate('automated-workspace')}
              disabled={!latestScanId}
              title={latestScanId ? 'Open the latest scan in Cockpit' : 'Run a scan first to open Cockpit'}
            >
              Open Cockpit
            </Button>
            <Button variant="ghost" onClick={() => onNavigate('repository')}>Repository Scan</Button>
            <Button variant="ghost" onClick={() => onNavigate('nuclei')}>Nuclei & CVE</Button>
          </div>
        </aside>
      </div>
    </div>
  );
}
