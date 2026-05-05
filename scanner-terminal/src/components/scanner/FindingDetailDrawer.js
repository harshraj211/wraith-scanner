import React from 'react';
import Drawer from '../ui/Drawer';
import SeverityBadge from '../ui/SeverityBadge';
import Button from '../ui/Button';

export default function FindingDetailDrawer({
  finding,
  evidenceArtifacts = [],
  evidenceState = 'idle',
  onClose,
  onRunProof,
  onExportEvidence,
}) {
  return (
    <Drawer
      open={Boolean(finding)}
      title={finding?.title || 'Finding'}
      onClose={onClose}
      actions={(
        <>
          <Button onClick={() => onRunProof?.(finding)}>Run Proof Task</Button>
          <Button variant="secondary" onClick={() => onExportEvidence?.(finding)}>Export Evidence</Button>
        </>
      )}
    >
      {finding && (
        <div className="finding-detail">
          <SeverityBadge severity={finding.severity} />
          <dl>
            <dt>Endpoint</dt><dd>{finding.normalized_endpoint || finding.target_url}</dd>
            <dt>Parameter</dt><dd>{finding.parameter_name || '-'}</dd>
            <dt>CWE</dt><dd>{finding.cwe || '-'}</dd>
            <dt>Proof</dt><dd>{finding.proof_status || 'not_attempted'}</dd>
          </dl>
          <h3>Discovery Evidence</h3>
          <pre>{finding.discovery_evidence || finding.evidence || 'No evidence loaded.'}</pre>
          <h3>Linked Evidence</h3>
          <div className="artifact-stack">
            {evidenceState === 'loading' && <p className="muted-text">Loading linked artifacts...</p>}
            {evidenceState !== 'loading' && evidenceArtifacts.length === 0 && (
              <p className="muted-text">No linked artifacts stored for this finding yet.</p>
            )}
            {evidenceState !== 'loading' && evidenceArtifacts.map((artifact) => (
              <article className="artifact-card" key={artifact.artifact_id}>
                <header>
                  <strong>{artifactLabel(artifact.artifact_type)}</strong>
                  <code>{artifact.artifact_id}</code>
                </header>
                {artifact.task_id && <span className="artifact-meta">task {artifact.task_id}</span>}
                <pre>{artifact.inline_excerpt || artifact.path || 'No inline excerpt stored.'}</pre>
              </article>
            ))}
          </div>
          <h3>Remediation</h3>
          <p>{finding.remediation || 'Validate the finding and apply least-privilege, allowlisting, encoding, or parameterization as appropriate.'}</p>
        </div>
      )}
    </Drawer>
  );
}

function artifactLabel(type) {
  return String(type || 'artifact').replace(/_/g, ' ');
}
