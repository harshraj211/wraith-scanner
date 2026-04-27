import React, { useEffect, useState } from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import DataTable from '../components/ui/DataTable';
import SeverityBadge from '../components/ui/SeverityBadge';
import FindingDetailDrawer from '../components/scanner/FindingDetailDrawer';

export default function Findings({
  findings = [],
  findingsState = 'idle',
  latestScanId,
  onNavigate,
  onRunProof,
  onRefresh,
}) {
  const [selected, setSelected] = useState(findings[0] || null);

  useEffect(() => {
    if (!findings.length) {
      setSelected(null);
      return;
    }
    if (!selected || !findings.some((finding) => finding.finding_id === selected.finding_id)) {
      setSelected(findings[0]);
    }
  }, [findings, selected]);

  return (
    <div className="page-fill">
      <PageHeader
        eyebrow="Findings"
        title="Findings"
        description="Triage live scanner findings, source/runtime context, and proof status."
        actions={(
          <>
            <Button variant="secondary" onClick={onRefresh} disabled={!latestScanId || findingsState === 'loading'}>
              {findingsState === 'loading' ? 'Loading' : 'Refresh'}
            </Button>
            <Button onClick={() => onNavigate('proof')}>Open Proof Mode</Button>
          </>
        )}
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
          rows={findings}
          rowKey="finding_id"
          onRowClick={setSelected}
          emptyTitle={latestScanId ? 'No findings returned by backend' : 'No scan selected'}
        />
        <FindingDetailDrawer finding={selected} onClose={() => setSelected(null)} onRunProof={onRunProof} />
      </div>
    </div>
  );
}
