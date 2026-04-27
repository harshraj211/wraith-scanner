import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';

export default function AutomatedScanSetup({ form, updateForm, submitScan, launchState, onNavigate }) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Automated"
        title="Automated Scan Setup"
        description="Configure target, authentication, API context, and sequence workflows."
        actions={<Button onClick={submitScan} disabled={launchState === 'starting'}>{launchState === 'starting' ? 'Launching' : 'Launch Scan'}</Button>}
      />
      <div className="setup-grid">
        <div className="page-stack">
          <Card title="Target Specification" eyebrow="Target">
            <label className="field">
              <span>Base URL</span>
              <input value={form.targetUrl} onChange={(event) => updateForm('targetUrl', event.target.value)} />
            </label>
          </Card>
          <Card title="Scan Configuration" eyebrow="Controls">
            <div className="form-grid">
              <label className="field">
                <span>Depth</span>
                <input type="number" min="1" max="8" value={form.depth} onChange={(event) => updateForm('depth', event.target.value)} />
              </label>
              <label className="field">
                <span>Timeout</span>
                <input type="number" min="1" max="60" value={form.timeout} onChange={(event) => updateForm('timeout', event.target.value)} />
              </label>
              <label className="field">
                <span>Safety Mode</span>
                <select value={form.safetyMode} onChange={(event) => updateForm('safetyMode', event.target.value)}>
                  <option value="safe">safe</option>
                  <option value="intrusive">intrusive</option>
                  <option value="lab">lab</option>
                </select>
              </label>
              <label className="field">
                <span>Auth Role</span>
                <input value={form.authRole} onChange={(event) => updateForm('authRole', event.target.value)} />
              </label>
            </div>
          </Card>
          <Card title="Authentication" eyebrow="Profiles">
            <div className="form-grid">
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
                <span>Bearer Token</span>
                <input value={form.bearerToken} onChange={(event) => updateForm('bearerToken', event.target.value)} />
              </label>
              <label className="field wide">
                <span>Headers</span>
                <textarea value={form.headers} onChange={(event) => updateForm('headers', event.target.value)} />
              </label>
              <label className="field wide">
                <span>Cookies</span>
                <textarea value={form.cookies} onChange={(event) => updateForm('cookies', event.target.value)} />
              </label>
            </div>
          </Card>
          <Card title="API Imports" eyebrow="Context">
            <div className="form-grid">
              <label className="field wide">
                <span>OpenAPI Imports</span>
                <textarea value={form.openapiImports} onChange={(event) => updateForm('openapiImports', event.target.value)} />
              </label>
              <label className="field wide">
                <span>Postman Imports</span>
                <textarea value={form.postmanImports} onChange={(event) => updateForm('postmanImports', event.target.value)} />
              </label>
              <label className="field wide">
                <span>HAR Imports</span>
                <textarea value={form.harImports} onChange={(event) => updateForm('harImports', event.target.value)} />
              </label>
              <label className="field wide">
                <span>GraphQL Imports</span>
                <textarea value={form.graphqlImports} onChange={(event) => updateForm('graphqlImports', event.target.value)} />
              </label>
            </div>
          </Card>
          <Card title="Sequence Workflows" eyebrow="Stateful API">
            <label className="field">
              <span>Sequence Workflows</span>
              <textarea value={form.sequenceWorkflows} onChange={(event) => updateForm('sequenceWorkflows', event.target.value)} />
            </label>
          </Card>
        </div>
        <Card title="Execution Summary" eyebrow="Ready">
          <div className="summary-list">
            <div><span>Target</span><strong>{form.targetUrl}</strong></div>
            <div><span>Depth</span><strong>{form.depth}</strong></div>
            <div><span>Auth</span><strong>{form.authType}</strong></div>
            <div><span>Safety</span><strong>{form.safetyMode}</strong></div>
          </div>
          <div className="button-column">
            <Button onClick={submitScan} disabled={launchState === 'starting'}>{launchState === 'starting' ? 'Launching' : 'Launch Scan'}</Button>
            <Button variant="secondary" onClick={() => onNavigate('automated-workspace')}>Open Workspace</Button>
          </div>
        </Card>
      </div>
    </div>
  );
}
