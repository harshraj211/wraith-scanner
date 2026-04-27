import React, { useState } from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import DataTable from '../components/ui/DataTable';
import SeverityBadge from '../components/ui/SeverityBadge';
import FindingDetailDrawer from '../components/scanner/FindingDetailDrawer';

export default function Findings({ findings = [], onNavigate, onRunProof }) {
  const [selected, setSelected] = useState(findings[0] || null);
  const rows = findings.length ? findings : mockFindings;
  return (
    <div className="page-fill">
      <PageHeader
        eyebrow="Findings"
        title="Findings"
        description="Triage confirmed vulnerabilities, source/runtime context, and proof status."
        actions={<Button onClick={() => onNavigate('proof')}>Open Proof Mode</Button>}
      />
      <div className="split-workspace">
        <DataTable
          columns={[
            { key: 'severity', label: 'Severity', width: '110px', render: (row) => <SeverityBadge severity={row.severity} /> },
            { key: 'title', label: 'Title', width: 'minmax(220px, 1fr)' },
            { key: 'normalized_endpoint', label: 'Endpoint', width: 'minmax(260px, 1fr)', render: (row) => row.normalized_endpoint || row.target_url },
            { key: 'method', label: 'Method', width: '82px' },
            { key: 'parameter_name', label: 'Parameter', width: '130px' },
            { key: 'cwe', label: 'CWE', width: '100px' },
            { key: 'proof_status', label: 'Proof', width: '140px' },
            { key: 'confidence', label: 'Conf', width: '80px' },
          ]}
          rows={rows}
          rowKey="finding_id"
          onRowClick={setSelected}
          emptyTitle="No findings loaded"
        />
        <FindingDetailDrawer finding={selected} onClose={() => setSelected(null)} onRunProof={onRunProof} />
      </div>
    </div>
  );
}

const mockFindings = [
  {
    finding_id: 'mock-sqli',
    title: 'Blind SQL Injection',
    severity: 'critical',
    normalized_endpoint: '/api/v2/user/profile/update',
    method: 'POST',
    parameter_name: 'user_uuid',
    cwe: 'CWE-89',
    proof_status: 'succeeded',
    confidence: 95,
    discovery_evidence: 'Time delta confirms SQL execution behavior.',
  },
  {
    finding_id: 'mock-ssrf',
    title: 'Server-Side Request Forgery',
    severity: 'high',
    normalized_endpoint: '/webhook/register',
    method: 'POST',
    parameter_name: 'callback_url',
    cwe: 'CWE-918',
    proof_status: 'not_attempted',
    confidence: 88,
    discovery_evidence: 'OOB callback candidate recorded.',
  },
];
