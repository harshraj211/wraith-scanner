import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import EmptyState from '../components/ui/EmptyState';

export default function Comparer(props) {
  return (
    <div className="page-stack lab-page comparer-page decoder-comparer-page">
      <PageHeader
        eyebrow="Manual"
        title="Comparer"
        description="Compare two captured responses by status, headers, JSON shape, body hash, size, and timing."
        actions={<ComparerActions {...props} />}
      />
      <ComparerPanel {...props} />
    </div>
  );
}

export function ComparerPanel({
  latestScanId,
  corpusRequests = [],
  comparerSelection = {},
  comparerState,
  comparerResult,
  updateComparerSelection,
  runComparer,
  loadCorpus,
  compact = false,
}) {
  const baseline = corpusRequests.find((item) => item.request_id === comparerSelection.baselineRequestId);
  const candidate = corpusRequests.find((item) => item.request_id === comparerSelection.candidateRequestId);
  const result = comparerResult || {};
  const headerRows = normalizeHeaderRows(result.header_changes);
  const bodyRows = normalizeBodyRows(result.json?.changes || result.body_changes);

  return (
    <section className={compact ? 'dc-panel comparer-panel compact' : 'dc-panel comparer-panel'}>
      <header className="dc-section-head">
        <div>
          <h2>Comparer</h2>
          <p>Compare two requests or responses side-by-side.</p>
        </div>
        <ComparerActions
          latestScanId={latestScanId}
          baseline={baseline}
          candidate={candidate}
          comparerState={comparerState}
          loadCorpus={loadCorpus}
          runComparer={runComparer}
        />
      </header>

      <div className="comparer-workbench">
        <aside className="comparison-summary">
          <h3>Comparison Summary</h3>
          <SummaryMetric label="Status" value={result.status_delta || '-'} tone={result.status_delta ? 'success' : ''} />
          <SummaryMetric label="Size" value={result.length_delta === undefined ? '-' : `${signed(result.length_delta)} B`} />
          <SummaryMetric label="Time" value={result.time_delta_ms === undefined ? '-' : `${signed(result.time_delta_ms)} ms`} />
          <SummaryMetric label="Headers" value={result.header_change_count ?? headerRows.length} />
          <SummaryMetric label="Body Lines" value={result.body_line_changes ?? result.json_change_count ?? bodyRows.length} tone={result.body_changed ? 'danger' : ''} />
          <SummaryMetric label="Words" value={result.word_delta ?? '-'} />
          <div className="comparison-legend">
            <span><i className="added" />Added</span>
            <span><i className="unchanged" />Unchanged</span>
            <span><i className="removed" />Removed</span>
          </div>
          <label className="check-row"><input type="checkbox" defaultChecked /><span>Headers</span></label>
          <label className="check-row"><input type="checkbox" defaultChecked /><span>Body</span></label>
          <label className="check-row"><input type="checkbox" defaultChecked /><span>Whitespace</span></label>
        </aside>

        <div className="comparison-main">
          <div className="comparison-selectors">
            <RequestSelect
              side="Left"
              value={comparerSelection.baselineRequestId}
              requests={corpusRequests}
              onChange={(value) => updateComparerSelection?.('baselineRequestId', value)}
            />
            <button type="button" className="swap-button" onClick={() => {
              updateComparerSelection?.('baselineRequestId', comparerSelection.candidateRequestId);
              updateComparerSelection?.('candidateRequestId', comparerSelection.baselineRequestId);
            }}>
              <span className="material-symbols-outlined">swap_horiz</span>
              Swap
            </button>
            <RequestSelect
              side="Right"
              value={comparerSelection.candidateRequestId}
              requests={corpusRequests}
              onChange={(value) => updateComparerSelection?.('candidateRequestId', value)}
            />
          </div>

          <div className="comparison-response-grid">
            <ResponseMeta title="Left Response Metadata" request={baseline} />
            <ResponseMeta title="Right Response Metadata" request={candidate} />
          </div>

          {!baseline || !candidate ? (
            <EmptyState
              icon="difference"
              title="Select two captured requests"
              body="Load a scan corpus, choose left and right requests, then run Compare."
            />
          ) : null}

          <DiffBlock
            title={`Header Diff (${headerRows.length} changes)`}
            rows={headerRows}
            columns={['Header', 'Left', 'Right', 'Diff']}
            emptyTitle="No header differences"
            emptyBody="Header changes will appear after a comparison is run."
          />
          <DiffBlock
            title={`Body Diff (${bodyRows.length} changes)`}
            rows={bodyRows}
            columns={['Line', 'Left', 'Right']}
            emptyTitle="No body differences"
            emptyBody="Body or JSON changes will appear after a comparison is run."
            body
          />
        </div>
      </div>
    </section>
  );
}

function ComparerActions({
  latestScanId,
  baseline: providedBaseline,
  candidate: providedCandidate,
  corpusRequests = [],
  comparerSelection = {},
  comparerState,
  loadCorpus,
  runComparer,
}) {
  const baseline = providedBaseline || corpusRequests.find((item) => item.request_id === comparerSelection.baselineRequestId);
  const candidate = providedCandidate || corpusRequests.find((item) => item.request_id === comparerSelection.candidateRequestId);
  const hasChosenPair = Boolean(baseline && candidate);
  return (
    <div className="page-actions">
      <Button variant="secondary" onClick={() => loadCorpus?.(latestScanId)} disabled={!latestScanId}>
        <span className="material-symbols-outlined">download</span>
        Load Corpus
      </Button>
      <Button onClick={runComparer} disabled={!hasChosenPair || comparerState === 'running'}>
        <span className="material-symbols-outlined">difference</span>
        {comparerState === 'running' ? 'Comparing' : 'Compare'}
      </Button>
    </div>
  );
}

function RequestSelect({ side, value, requests, onChange }) {
  return (
    <label className="dc-select">
      <span>{side}</span>
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

function ResponseMeta({ title, request }) {
  if (!request) {
    return (
      <div className="response-meta empty">
        <strong>{title}</strong>
        <EmptyState
          icon="article"
          title="No response selected"
          body="Choose a captured request from the corpus."
        />
      </div>
    );
  }

  const response = request.response || {};
  const headers = response.headers || {};
  const headerValue = (...keys) => keys.map((key) => headers[key]).find(Boolean);
  const lines = [
    `HTTP/1.1 ${response.status_code || '---'} ${response.reason || ''}`.trim(),
    headerValue('date', 'Date') ? `Date: ${headerValue('date', 'Date')}` : null,
    headerValue('server', 'Server') ? `Server: ${headerValue('server', 'Server')}` : null,
    headerValue('content-type', 'Content-Type') ? `Content-Type: ${headerValue('content-type', 'Content-Type')}` : null,
    response.content_length !== undefined ? `Content-Length: ${response.content_length}` : null,
    headerValue('connection', 'Connection') ? `Connection: ${headerValue('connection', 'Connection')}` : null,
    headerValue('x-request-id', 'X-Request-ID') ? `X-Request-ID: ${headerValue('x-request-id', 'X-Request-ID')}` : null,
  ].filter(Boolean);

  return (
    <div className="response-meta">
      <strong>{title}</strong>
      <pre>{lines.length ? lines.join('\n') : 'No response metadata captured.'}</pre>
    </div>
  );
}

function DiffBlock({ title, rows, columns, emptyTitle, emptyBody, body = false }) {
  return (
    <section className={body ? 'dc-diff-block body' : 'dc-diff-block'}>
      <header>
        <span className="material-symbols-outlined">expand_more</span>
        <strong>{title}</strong>
      </header>
      <div className="dc-diff-table">
        <div className="dc-diff-row head" style={{ gridTemplateColumns: columns.map(() => 'minmax(0, 1fr)').join(' ') }}>
          {columns.map((column) => <span key={column}>{column}</span>)}
        </div>
        {rows.length ? rows.map((row, index) => (
          <div
            className={`dc-diff-row ${row.change || ''}`}
            key={`${row.name || row.path || row.line}-${index}`}
            style={{ gridTemplateColumns: columns.map(() => 'minmax(0, 1fr)').join(' ') }}
          >
            {columns.map((column) => <code key={column}>{row[cellKey(column)] || '-'}</code>)}
          </div>
        )) : (
          <EmptyState icon="data_object" title={emptyTitle} body={emptyBody} />
        )}
      </div>
    </section>
  );
}

function SummaryMetric({ label, value, tone = '' }) {
  return (
    <div className="summary-metric">
      <span>{label}</span>
      <strong className={tone ? `tone-${tone}` : ''}>{value}</strong>
    </div>
  );
}

function normalizeHeaderRows(rows = []) {
  return rows.slice(0, 10).map((row) => {
    const change = normalizeChange(row.change);
    return {
      header: row.name || row.path || '-',
      left: formatCell(row.previous),
      right: formatCell(row.current),
      diff: row.change || 'Changed',
      change,
    };
  });
}

function normalizeBodyRows(rows = []) {
  return rows.slice(0, 12).map((row, index) => ({
    line: row.path || row.line || index + 1,
    left: formatCell(row.previous),
    right: formatCell(row.current),
    change: normalizeChange(row.change),
  }));
}

function normalizeChange(change) {
  const value = String(change || 'changed').toLowerCase();
  if (value === 'added') return 'added';
  if (value === 'removed') return 'removed';
  if (value === 'unchanged') return 'unchanged';
  return 'changed';
}

function cellKey(column) {
  if (column === 'Header') return 'header';
  if (column === 'Line') return 'line';
  if (column === 'Left') return 'left';
  if (column === 'Right') return 'right';
  if (column === 'Diff') return 'diff';
  return column.toLowerCase();
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
