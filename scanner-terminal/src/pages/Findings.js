import React, { useEffect, useState } from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import DataTable from '../components/ui/DataTable';
import SkeletonTable from '../components/ui/SkeletonTable';
import SeverityBadge from '../components/ui/SeverityBadge';
import FindingDetailDrawer from '../components/scanner/FindingDetailDrawer';

export default function Findings({
  findings = [],
  findingsState = 'idle',
  latestScanId,
  corpusRequests = [],
  evidenceArtifacts = [],
  evidenceState = 'idle',
  onNavigate,
  onRunProof,
  onExportEvidence,
  onRefresh,
  onLoadEvidence,
  loadExchange,
  sendRequestToRepeater,
}) {
  const [selected, setSelected] = useState(findings[0] || null);
  const selectedFindingId = selected?.finding_id || '';
  const linkedRequest = findLinkedRequest(selected, corpusRequests);

  useEffect(() => {
    if (!findings.length) {
      setSelected(null);
      return;
    }
    if (!selected || !findings.some((finding) => finding.finding_id === selected.finding_id)) {
      setSelected(findings[0]);
    }
  }, [findings, selected]);

  useEffect(() => {
    onLoadEvidence?.(selectedFindingId);
  }, [onLoadEvidence, selectedFindingId]);

  const viewLinkedRequest = async (finding) => {
    const request = findLinkedRequest(finding, corpusRequests);
    if (request?.request_id) await loadExchange?.(request.request_id);
    onNavigate('evidence');
  };

  const sendLinkedRequestToRepeater = (finding) => {
    const request = findLinkedRequest(finding, corpusRequests);
    if (request) {
      sendRequestToRepeater?.(request);
    } else {
      onNavigate('evidence');
    }
  };

  return (
    <div className="page-fill lab-page findings-page">
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
        {findingsState === 'loading' ? (
          <SkeletonTable rows={8} columns={8} />
        ) : (
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
        )}
        <FindingDetailDrawer
          finding={selected}
          evidenceArtifacts={evidenceArtifacts}
          evidenceState={evidenceState}
          onClose={() => setSelected(null)}
          onRunProof={onRunProof}
          onExportEvidence={onExportEvidence}
          onViewRequest={viewLinkedRequest}
          onSendToRepeater={sendLinkedRequestToRepeater}
          hasLinkedRequest={Boolean(linkedRequest)}
        />
      </div>
    </div>
  );
}

function findLinkedRequest(finding, requests) {
  if (!finding || !Array.isArray(requests)) return null;
  if (finding.request_id) {
    const direct = requests.find((request) => request.request_id === finding.request_id);
    if (direct) return direct;
  }
  const targetUrl = String(finding.target_url || finding.url || '').trim();
  const endpoint = String(finding.normalized_endpoint || finding.endpoint || '').trim();
  return requests.find((request) => {
    const requestUrl = String(request.url || '');
    const requestEndpoint = String(request.normalized_endpoint || '');
    return (targetUrl && requestUrl === targetUrl)
      || (endpoint && requestEndpoint === endpoint)
      || (endpoint && requestUrl.includes(endpoint));
  }) || null;
}
