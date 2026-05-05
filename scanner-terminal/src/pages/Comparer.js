import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import DataTable from '../components/ui/DataTable';

export default function Comparer({
  latestScanId,
  corpusRequests = [],
  comparerSelection,
  comparerState,
  comparerResult,
  updateComparerSelection,
  runComparer,
  loadCorpus,
}) {
  const baseline = corpusRequests.find((item) => item.request_id === comparerSelection.baselineRequestId);
  const candidate = corpusRequests.find((item) => item.request_id === comparerSelection.candidateRequestId);
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Manual"
        title="Comparer"
        description="Compare two captured responses by status, headers, JSON shape, body hash, size, and timing."
        actions={(
          <>
            <Button variant="secondary" onClick={() => loadCorpus?.(latestScanId)} disabled={!latestScanId}>Load corpus</Button>
            <Button onClick={runComparer} disabled={!baseline || !candidate || comparerState === 'running'}>
              {comparerState === 'running' ? 'Comparing' : 'Compare'}
            </Button>
          </>
        )}
      />

      <div className="comparer-grid">
        <Card title="Baseline" eyebrow="Previous Response">
          <RequestSelect
            label="Baseline request"
            value={comparerSelection.baselineRequestId}
            requests={corpusRequests}
            onChange={(value) => updateComparerSelection('baselineRequestId', value)}
          />
          <RequestSummary request={baseline} />
        </Card>
        <Card title="Candidate" eyebrow="Current Response">
          <RequestSelect
            label="Candidate request"
            value={comparerSelection.candidateRequestId}
            requests={corpusRequests}
            onChange={(value) => updateComparerSelection('candidateRequestId', value)}
          />
          <RequestSummary request={candidate} />
        </Card>
      </div>

      <Card title="Comparison Result" eyebrow={comparerState}>
        {!comparerResult && <p className="muted-text">Choose two captured requests with responses, then run Compare.</p>}
        {comparerResult && (
          <div className="comparer-results">
            <div className="repeater-diff">
              <Metric label="Status" value={comparerResult.status_delta} />
              <Metric label="Length" value={`${signed(comparerResult.length_delta)} B`} />
              <Metric label="Time" value={`${signed(comparerResult.time_delta_ms)} ms`} />
              <Metric label="Body" value={comparerResult.body_changed ? 'changed' : 'same'} />
              <Metric label="Headers" value={comparerResult.header_change_count || 0} />
              <Metric label="JSON" value={comparerResult.json_change_count || 0} />
            </div>
            <div className="comparer-result-grid">
              <DiffTable
                title="Header Diff"
                rows={comparerResult.header_changes || []}
                columns={[
                  { key: 'name', label: 'Header', width: 'minmax(130px, .7fr)' },
                  { key: 'previous', label: 'Previous', width: 'minmax(180px, 1fr)' },
                  { key: 'current', label: 'Current', width: 'minmax(180px, 1fr)' },
                  { key: 'change', label: 'Change', width: '100px' },
                ]}
              />
              <DiffTable
                title="JSON Semantic Diff"
                rows={comparerResult.json?.changes || []}
                emptyTitle={comparerResult.json?.comparable ? 'No JSON value changes' : 'Responses are not both JSON'}
                columns={[
                  { key: 'path', label: 'Path', width: 'minmax(180px, .8fr)' },
                  { key: 'previous', label: 'Previous', width: 'minmax(160px, 1fr)' },
                  { key: 'current', label: 'Current', width: 'minmax(160px, 1fr)' },
                  { key: 'change', label: 'Change', width: '110px' },
                ]}
              />
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function RequestSelect({ label, value, requests, onChange }) {
  return (
    <label className="field">
      <span>{label}</span>
      <select value={value || ''} onChange={(event) => onChange(event.target.value)}>
        <option value="">Select captured request</option>
        {requests.map((request) => (
          <option key={request.request_id} value={request.request_id}>
            {request.method} {shortUrl(request.url)} {request.response?.status_code ? `(${request.response.status_code})` : ''}
          </option>
        ))}
      </select>
    </label>
  );
}

function RequestSummary({ request }) {
  if (!request) return <p className="muted-text">No request selected.</p>;
  return (
    <dl className="request-summary">
      <dt>Method</dt><dd>{request.method}</dd>
      <dt>URL</dt><dd>{request.url}</dd>
      <dt>Status</dt><dd>{request.response?.status_code || '-'}</dd>
      <dt>Length</dt><dd>{request.response?.content_length || 0} B</dd>
      <dt>Time</dt><dd>{request.response?.response_time_ms || 0} ms</dd>
      <dt>Source</dt><dd>{request.source || '-'}</dd>
    </dl>
  );
}

function DiffTable({ title, rows, columns, emptyTitle }) {
  return (
    <section className="comparer-diff-panel">
      <h3>{title}</h3>
      <DataTable
        columns={columns.map((column) => ({
          ...column,
          render: (row) => <code>{formatCell(row[column.key])}</code>,
        }))}
        rows={rows}
        rowKey="path"
        emptyTitle={emptyTitle || `No ${title.toLowerCase()} changes`}
      />
    </section>
  );
}

function Metric({ label, value }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}

function signed(value) {
  const numeric = Number(value || 0);
  return `${numeric >= 0 ? '+' : ''}${numeric}`;
}

function shortUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.pathname || '/';
  } catch (_error) {
    return url;
  }
}

function formatCell(value) {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch (_error) {
    return String(value);
  }
}
