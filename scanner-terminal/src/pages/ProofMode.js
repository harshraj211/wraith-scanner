import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import DataTable from '../components/ui/DataTable';
import ProofTaskPanel from '../components/scanner/ProofTaskPanel';
import EvidenceTable from '../components/scanner/EvidenceTable';
import RequestResponseViewer from '../components/scanner/RequestResponseViewer';

export default function ProofMode({
  findings = [],
  proofState,
  proofTasks = [],
  evidenceArtifacts = [],
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
        <Card title="Proof Requests" eyebrow={`${proofRequests.length} corpus exchanges`}>
          <EvidenceTable
            requests={proofRequests}
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
