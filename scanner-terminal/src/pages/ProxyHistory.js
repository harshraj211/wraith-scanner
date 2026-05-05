import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EvidenceTable from '../components/scanner/EvidenceTable';
import RequestResponseViewer from '../components/scanner/RequestResponseViewer';

export default function ProxyHistory({
  latestScanId,
  proxyStatus,
  proxyState,
  pendingProxyRequests,
  startManualProxy,
  stopManualProxy,
  refreshProxyStatus,
  toggleManualProxyIntercept,
  loadProxyPending,
  decideProxyRequest,
  runPassiveScan,
  passiveState,
  corpusRequests,
  selectedExchange,
  corpusFilters,
  updateCorpusFilter,
  loadCorpus,
  loadExchange,
  sendRequestToRepeater,
  sendRequestToIntruder,
  browserState,
  browserStatus,
  openWraithBrowser,
  closeWraithBrowser,
}) {
  return (
    <div className="page-fill">
      <PageHeader
        eyebrow="Manual Proxy"
        title="Proxy History"
        description="HTTP capture with pause, forward, drop, and edit-before-forward."
        actions={(
          <>
            <Button variant="secondary" onClick={refreshProxyStatus}>Status</Button>
            <Button variant="secondary" onClick={runPassiveScan} disabled={!latestScanId || passiveState === 'running'}>{passiveState === 'running' ? 'Passive scanning' : 'Run passive scan'}</Button>
            <Button variant="secondary" onClick={openWraithBrowser} disabled={browserState === 'opening'}>
              {browserState === 'opening' ? 'Opening...' : 'Open browser'}
            </Button>
            {proxyStatus?.running ? <Button variant="danger" onClick={stopManualProxy}>Stop proxy</Button> : <Button onClick={startManualProxy}>Start proxy</Button>}
          </>
        )}
      />
      <div className="proxy-grid">
        <Card title="Live Capture" eyebrow="Proxy">
          <div className="proxy-stats">
            <Metric label="State" value={proxyState || (proxyStatus?.running ? 'running' : 'stopped')} />
            <Metric label="Host" value={`${proxyStatus?.host || '127.0.0.1'}:${proxyStatus?.port || '-'}`} />
            <Metric label="Pending" value={pendingProxyRequests.length} />
            <Metric label="Browser" value={browserStatus?.running ? 'open' : 'closed'} />
          </div>
          <label className="check-row">
            <input type="checkbox" checked={Boolean(proxyStatus?.intercept_enabled)} onChange={(event) => toggleManualProxyIntercept(event.target.checked)} />
            <span>Pause requests for forward/drop</span>
          </label>
          <Button variant="secondary" onClick={loadProxyPending}>Load pending</Button>
          {browserStatus?.running && (
            <Button variant="ghost" onClick={closeWraithBrowser}>Close browser</Button>
          )}
          <div className="pending-list">
            {pendingProxyRequests.map((item) => (
              <div className="pending-row" key={item.request_id}>
                <code>{item.method} {item.url}</code>
                <Button variant="secondary" onClick={() => decideProxyRequest(item.request_id, 'forward')}>Forward</Button>
                <Button variant="danger" onClick={() => decideProxyRequest(item.request_id, 'drop')}>Drop</Button>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Captured Requests" eyebrow={latestScanId || 'Corpus'}>
          <div className="filter-bar">
            <input placeholder="path contains" value={corpusFilters?.pathContains || ''} onChange={(event) => updateCorpusFilter?.('pathContains', event.target.value)} />
            <select value={corpusFilters?.method || ''} onChange={(event) => updateCorpusFilter?.('method', event.target.value)}>
              <option value="">Any method</option>
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>PATCH</option>
              <option>DELETE</option>
            </select>
            <select value={corpusFilters?.statusCode || ''} onChange={(event) => updateCorpusFilter?.('statusCode', event.target.value)}>
              <option value="">Any status</option>
              <option value="200">200</option>
              <option value="300">300</option>
              <option value="400">400</option>
              <option value="500">500</option>
            </select>
            <Button variant="secondary" onClick={() => loadCorpus?.(latestScanId)} disabled={!latestScanId}>Refresh</Button>
          </div>
          <EvidenceTable
            requests={corpusRequests}
            selectedExchange={selectedExchange}
            onSelect={loadExchange}
            onSendToRepeater={sendRequestToRepeater}
            onSendToIntruder={sendRequestToIntruder}
          />
        </Card>
        <Card title="Selected Exchange" eyebrow="Inspector">
          <RequestResponseViewer exchange={selectedExchange} />
        </Card>
      </div>
    </div>
  );
}

function Metric({ label, value }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}
