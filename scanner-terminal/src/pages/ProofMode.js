import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import ProofTaskPanel from '../components/scanner/ProofTaskPanel';
import EvidenceTable from '../components/scanner/EvidenceTable';

export default function ProofMode({ findings, proofState, onCreateProof, onRunProof, corpusRequests, loadExchange }) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Proof Mode"
        title="Safe Proof Mode"
        description="Create deterministic proof tasks from high-confidence findings. LLMs are not used to generate arbitrary payloads."
        actions={<Button variant="secondary" disabled>{proofState || 'safe mode'}</Button>}
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
      <section className="card">
        <div className="card-header"><div><span className="eyebrow">Proof Evidence</span><h2>Proof Requests</h2></div></div>
        <div className="card-body">
          <EvidenceTable requests={corpusRequests.filter((item) => item.source === 'proof')} onSelect={loadExchange} />
        </div>
      </section>
    </div>
  );
}
