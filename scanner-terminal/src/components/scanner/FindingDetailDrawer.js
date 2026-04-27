import React from 'react';
import Drawer from '../ui/Drawer';
import SeverityBadge from '../ui/SeverityBadge';
import Button from '../ui/Button';

export default function FindingDetailDrawer({ finding, onClose, onRunProof }) {
  return (
    <Drawer
      open={Boolean(finding)}
      title={finding?.title || 'Finding'}
      onClose={onClose}
      actions={(
        <>
          <Button onClick={() => onRunProof?.(finding)}>Run Proof Task</Button>
          <Button variant="secondary">Export Evidence</Button>
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
          <h3>Remediation</h3>
          <p>{finding.remediation || 'Validate the finding and apply least-privilege, allowlisting, encoding, or parameterization as appropriate.'}</p>
        </div>
      )}
    </Drawer>
  );
}
