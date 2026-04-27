import React from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import EmptyState from '../ui/EmptyState';
import SeverityBadge from '../ui/SeverityBadge';

export default function ProofTaskPanel({ findings = [], onCreateProof, onRunProof }) {
  const proofReady = findings.filter((finding) => ['critical', 'high'].includes(String(finding.severity || '').toLowerCase()));
  return (
    <Card title="Proof-Ready Findings" eyebrow="Safe Proof Mode">
      {proofReady.length === 0 ? (
        <EmptyState title="No proof-ready findings" body="Run a scan and load high-confidence findings to create proof tasks." />
      ) : (
        <div className="proof-list">
          {proofReady.map((finding) => (
            <div className="proof-row" key={finding.finding_id || finding.title}>
              <SeverityBadge severity={finding.severity} />
              <span>{finding.title}</span>
              <em>{finding.proof_status || 'not_attempted'}</em>
              <Button variant="secondary" onClick={() => onCreateProof?.(finding)}>Create</Button>
              <Button onClick={() => onRunProof?.(finding)}>Run</Button>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
