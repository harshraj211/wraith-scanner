import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import CodeEditorPanel from '../components/ui/CodeEditorPanel';
import DataTable from '../components/ui/DataTable';
import ProofTaskPanel from '../components/scanner/ProofTaskPanel';
import EvidenceTable from '../components/scanner/EvidenceTable';
import RequestResponseViewer from '../components/scanner/RequestResponseViewer';

export default function ProofMode({
  findings = [],
  proofState,
  proofTasks = [],
  evidenceArtifacts = [],
  latestScanId,
  authzProfilesText = '',
  authzMatrixState = 'idle',
  authzMatrixResult,
  updateAuthzProfilesText,
  runAuthorizationMatrix,
  onCreateProof,
  onRunProof,
  onRefresh,
  corpusRequests = [],
  selectedExchange,
  loadExchange,
  sendRequestToRepeater,
  sendRequestToIntruder,
}) {
  const proofRequests = corpusRequests.filter((item) => item.source === 'proof');
  const authzRequests = corpusRequests.filter((item) => item.source === 'authz');
  const authzFindings = authzMatrixResult?.findings || [];
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Proof Mode"
        title="Safe Proof Mode"
        description="Create deterministic proof tasks from backend findings and store sanitized evidence."
        actions={(
          <>
            <Button variant="secondary" onClick={() => onRefresh?.()} disabled={proofState === 'loading'}>
              {proofState === 'loading' ? 'Loading' : 'Refresh proof data'}
            </Button>
            <Button variant="secondary" disabled>{proofState || 'safe mode'}</Button>
          </>
        )}
      />
      <div className="proof-grid">
        <ProofTaskPanel findings={findings} onCreateProof={onCreateProof} onRunProof={onRunProof} />
        <section className="proof-policy-card">
          <span className="eyebrow">Safety Policy</span>
          <h2>Non-destructive by default</h2>
          <ul>
            <li>Scope enforcement before proof execution.</li>
            <li>Strict attempt budgets.</li>
            <li>No sensitive data extraction.</li>
            <li>Sanitized evidence artifacts only.</li>
          </ul>
        </section>
      </div>

      <div className="authz-matrix-grid">
        <Card title="Authorization Matrix / BOLA" eyebrow="Role Diff Engine">
          <div className="authz-matrix-form">
            <p>
              Paste two or more auth profiles as JSON. The first profile is treated as the baseline owner role;
              Wraith replays object-specific read requests under the remaining roles in safe mode.
            </p>
            <CodeEditorPanel
              title="Auth profiles JSON"
              value={authzProfilesText}
              onChange={updateAuthzProfilesText}
              minRows={8}
              placeholder="Paste an auth profile JSON array for authorized test roles."
            />
            <div className="authz-matrix-actions">
              <Button onClick={runAuthorizationMatrix} disabled={!latestScanId || authzMatrixState === 'running'}>
                {authzMatrixState === 'running' ? 'Running matrix' : 'Run matrix'}
              </Button>
              <span>{latestScanId ? `scan ${latestScanId}` : 'No scan selected'}</span>
            </div>
          </div>
        </Card>
        <Card title="Matrix Results" eyebrow={authzMatrixState}>
          <div className="authz-result-strip">
            <div><span>Compared</span><strong>{authzMatrixResult?.compared_requests || 0}</strong></div>
            <div><span>Findings</span><strong>{authzFindings.length}</strong></div>
            <div><span>Skipped</span><strong>{authzMatrixResult?.skipped_requests?.length || 0}</strong></div>
            <div><span>Roles</span><strong>{authzMatrixResult?.roles?.length || 0}</strong></div>
          </div>
          <DataTable
            columns={[
              { key: 'title', label: 'Finding', width: 'minmax(220px, 1fr)' },
              { key: 'auth_role', label: 'Compared role', width: '150px' },
              { key: 'confidence', label: 'Conf', width: '80px' },
              { key: 'normalized_endpoint', label: 'Endpoint', width: 'minmax(220px, 1fr)' },
            ]}
            rows={authzFindings}
            rowKey="finding_id"
            emptyTitle="No matrix findings"
          />
        </Card>
      </div>

      <div className="proof-data-grid">
        <Card title="Proof Tasks" eyebrow={`${proofTasks.length} tasks`}>
          <DataTable
            columns={[
              { key: 'task_id', label: 'Task', width: 'minmax(220px, 1fr)' },
              { key: 'finding_id', label: 'Finding', width: 'minmax(220px, 1fr)' },
              { key: 'safety_mode', label: 'Mode', width: '90px' },
              { key: 'status', label: 'Status', width: '110px' },
              { key: 'result', label: 'Result', width: '110px' },
            ]}
            rows={proofTasks}
            rowKey="task_id"
            emptyTitle="No proof tasks created"
          />
        </Card>
        <Card title="Evidence Artifacts" eyebrow={`${evidenceArtifacts.length} artifacts`}>
          <DataTable
            columns={[
              { key: 'artifact_type', label: 'Type', width: '140px' },
              { key: 'finding_id', label: 'Finding', width: 'minmax(200px, 1fr)' },
              { key: 'task_id', label: 'Task', width: 'minmax(160px, 1fr)' },
              { key: 'inline_excerpt', label: 'Excerpt', width: 'minmax(260px, 1.2fr)' },
            ]}
            rows={evidenceArtifacts}
            rowKey="artifact_id"
            emptyTitle="No proof evidence artifacts stored"
          />
        </Card>
      </div>

      <div className="corpus-layout">
        <Card title="Proof & Authz Requests" eyebrow={`${proofRequests.length + authzRequests.length} corpus exchanges`}>
          <EvidenceTable
            requests={[...proofRequests, ...authzRequests]}
            selectedExchange={selectedExchange}
            onSelect={loadExchange}
            onSendToRepeater={sendRequestToRepeater}
            onSendToIntruder={sendRequestToIntruder}
          />
        </Card>
        <Card title="Proof HTTP Evidence" eyebrow="Inspector">
          <RequestResponseViewer exchange={selectedExchange} />
        </Card>
      </div>
    </div>
  );
}
