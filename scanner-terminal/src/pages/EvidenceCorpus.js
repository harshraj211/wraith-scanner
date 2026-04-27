import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EvidenceTable from '../components/scanner/EvidenceTable';
import RequestResponseViewer from '../components/scanner/RequestResponseViewer';

export default function EvidenceCorpus({
  latestScanId,
  corpusRequests,
  selectedExchange,
  corpusFilters,
  updateCorpusFilter,
  loadCorpus,
  loadExchange,
  sendRequestToRepeater,
  sendRequestToIntruder,
}) {
  return (
    <div className="page-fill">
      <PageHeader
        eyebrow="Corpus"
        title="Evidence Corpus"
        description="Search, inspect, and replay sanitized request/response evidence."
        actions={<Button onClick={() => loadCorpus(latestScanId)} disabled={!latestScanId}>Load Corpus</Button>}
      />
      <div className="corpus-layout">
        <Card title="Requests" eyebrow="Traffic">
          <div className="filter-bar">
            <input placeholder="path contains" value={corpusFilters.pathContains} onChange={(event) => updateCorpusFilter('pathContains', event.target.value)} />
            <select value={corpusFilters.method} onChange={(event) => updateCorpusFilter('method', event.target.value)}>
              <option value="">Any method</option>
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>PATCH</option>
              <option>DELETE</option>
            </select>
            <select value={corpusFilters.source} onChange={(event) => updateCorpusFilter('source', event.target.value)}>
              <option value="">Any source</option>
              <option value="crawler">crawler</option>
              <option value="import">import</option>
              <option value="proxy">proxy</option>
              <option value="manual">manual</option>
              <option value="replay">replay</option>
              <option value="fuzzer">fuzzer</option>
              <option value="proof">proof</option>
            </select>
            <input placeholder="status" value={corpusFilters.statusCode} onChange={(event) => updateCorpusFilter('statusCode', event.target.value)} />
          </div>
          <EvidenceTable
            requests={corpusRequests}
            selectedExchange={selectedExchange}
            onSelect={loadExchange}
            onSendToRepeater={sendRequestToRepeater}
            onSendToIntruder={sendRequestToIntruder}
          />
        </Card>
        <Card title="HTTP Evidence" eyebrow="Inspector">
          <RequestResponseViewer exchange={selectedExchange} />
        </Card>
      </div>
    </div>
  );
}
