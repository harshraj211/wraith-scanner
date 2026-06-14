import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import MetricCard from '../components/ui/MetricCard';
import RequestResponseViewer from '../components/scanner/RequestResponseViewer';
import { ManualRequestFields } from './Repeater';

export default function ManualTesting({
  latestScanId,
  onNavigate,
  manualRequest,
  updateManualRequest,
  sendManualReplay,
  saveManualRequest,
  manualState,
  manualFinding,
  manualFindingState,
  updateManualFinding,
  createManualFinding,
  selectedExchange,
  activeRepeaterTab,
  proxyStatus,
  corpusRequests,
  proxyCaStatus,
  proxyCaState,
  refreshProxyCaStatus,
  generateProxyCa,
  downloadProxyCa,
  generateProxyLeafCertificate,
  browserState,
  browserStatus,
  openWraithBrowser,
  closeWraithBrowser,
}) {
  const [leafHost, setLeafHost] = React.useState('');
  const [leafStatus, setLeafStatus] = React.useState(null);
  const [leafState, setLeafState] = React.useState('idle');
  const latestAttempt = activeRepeaterTab?.attempts?.find((attempt) => attempt.attemptId === activeRepeaterTab?.activeAttemptId)
    || activeRepeaterTab?.attempts?.[0]
    || null;
  const replayExchange = latestAttempt?.exchange || selectedExchange;

  const handleGenerateLeaf = async () => {
    if (!leafHost.trim() || !generateProxyLeafCertificate) return;
    setLeafState('generating');
    try {
      const status = await generateProxyLeafCertificate(leafHost.trim());
      setLeafStatus(status);
      setLeafState('ready');
    } catch (error) {
      setLeafStatus({ warning: error?.response?.data?.error || error?.response?.data?.warning || error.message });
      setLeafState('error');
    }
  };

  return (
    <div className="page-fill lab-page manual-page manual-workbench-page">
      <PageHeader
        eyebrow="Manual Testing"
        title="Workbench"
        description="Manual request composer, proxy capture, repeater, intruder, decoder, comparer, and evidence workflows."
        actions={(
          <>
            <Button variant="secondary" onClick={openWraithBrowser} disabled={browserState === 'opening'}>
              {browserState === 'opening' ? 'Opening...' : 'Open Browser'}
            </Button>
            <Button variant="secondary" onClick={() => onNavigate('proxy')}>Proxy History</Button>
            <Button onClick={sendManualReplay} disabled={manualState === 'sending'}>
              {manualState === 'sending' ? 'Sending' : 'Send'}
            </Button>
          </>
        )}
      />

      <div className="metric-grid five manual-command-strip">
        <MetricCard label="Proxy" value={proxyStatus?.running ? 'Running' : 'Stopped'} tone={proxyStatus?.running ? 'emerald' : 'slate'} />
        <MetricCard label="Browser" value={browserStatus?.running ? 'Open' : 'Closed'} tone={browserStatus?.running ? 'emerald' : 'slate'} />
        <MetricCard label="Captured" value={corpusRequests.length} tone="cyan" />
        <MetricCard label="Local CA" value={proxyCaStatus?.generated ? 'Ready' : 'Missing'} tone={proxyCaStatus?.generated ? 'emerald' : 'amber'} />
        <MetricCard label="Scan" value={latestScanId || 'None'} detail="active context" tone={latestScanId ? 'blue' : 'slate'} />
      </div>

      <div className="manual-workbench-grid">
        <Card
          title="Request"
          eyebrow="Manual composer"
          actions={(
            <>
              <Button variant="secondary" onClick={saveManualRequest} disabled={manualState === 'saving'}>
                {manualState === 'saving' ? 'Saving' : 'Save'}
              </Button>
              <Button onClick={sendManualReplay} disabled={manualState === 'sending'}>
                {manualState === 'sending' ? 'Sending' : 'Send'}
              </Button>
            </>
          )}
        >
          <ManualRequestFields request={manualRequest} updateRequest={updateManualRequest} compact />
        </Card>

        <Card
          title="Response"
          eyebrow={latestAttempt ? `${latestAttempt.status} / ${latestAttempt.timeMs || 0}ms` : 'Inspector'}
          actions={(
            <>
              <Button variant="ghost" onClick={() => onNavigate('repeater')}>Repeater</Button>
              <Button variant="ghost" onClick={() => onNavigate('intruder')}>Intruder</Button>
            </>
          )}
        >
          <RequestResponseViewer exchange={replayExchange} />
        </Card>

        <Card title="Manual Finding" eyebrow="Evidence">
          <div className="manual-finding-form terminal-finding-form">
            <div className="workflow-mini-grid">
              <label className="field">
                <span>Name</span>
                <input placeholder="Hardcoded Credential" value={manualFinding?.title || ''} onChange={(event) => updateManualFinding?.('title', event.target.value)} />
              </label>
              <label className="field">
                <span>Severity</span>
                <select value={manualFinding?.severity || 'medium'} onChange={(event) => updateManualFinding?.('severity', event.target.value)}>
                  <option>critical</option>
                  <option>high</option>
                  <option>medium</option>
                  <option>low</option>
                  <option>info</option>
                </select>
              </label>
            </div>
            <div className="workflow-mini-grid">
              <label className="field">
                <span>Endpoint</span>
                <input placeholder="/api/v1/auth/login" value={manualFinding?.vulnType || ''} onChange={(event) => updateManualFinding?.('vulnType', event.target.value)} />
              </label>
              <label className="field">
                <span>Parameter</span>
                <input placeholder="password" value={manualFinding?.parameterName || ''} onChange={(event) => updateManualFinding?.('parameterName', event.target.value)} />
              </label>
            </div>
            <label className="field">
              <span>Evidence</span>
              <textarea rows={3} placeholder="Hardcoded password accepted." value={manualFinding?.evidence || ''} onChange={(event) => updateManualFinding?.('evidence', event.target.value)} />
            </label>
            <label className="field">
              <span>Remediation</span>
              <textarea rows={2} placeholder="Rotate credentials and remove static secrets." value={manualFinding?.remediation || ''} onChange={(event) => updateManualFinding?.('remediation', event.target.value)} />
            </label>
            <Button onClick={createManualFinding} disabled={!latestScanId || !manualFinding?.title || manualFindingState === 'saving'}>
              {manualFindingState === 'saving' ? 'Saving Finding' : 'Save Finding'}
            </Button>
          </div>
        </Card>

        <Card title="Capture Controls" eyebrow="Proxy and CA">
          <div className="capture-control-grid">
            <div>
              <span>Proxy</span>
              <code>{proxyStatus?.running ? `${proxyStatus.host}:${proxyStatus.port}` : 'not listening'}</code>
            </div>
            <div>
              <span>Browser</span>
              <code>{browserStatus?.running ? 'profile active' : 'created on launch'}</code>
            </div>
            <div>
              <span>CA</span>
              <code>{proxyCaStatus?.generated ? 'generated' : proxyCaStatus?.warning || 'not generated'}</code>
            </div>
            <div>
              <span>CONNECT Guard</span>
              <code>{proxyStatus?.https_connect_blocked_count || 0} blocked</code>
            </div>
          </div>
          <div className="button-row">
            <Button variant="secondary" onClick={openWraithBrowser} disabled={browserState === 'opening'}>
              {browserState === 'opening' ? 'Opening' : 'Open Through Proxy'}
            </Button>
            <Button variant="ghost" onClick={closeWraithBrowser} disabled={!browserStatus?.running || browserState === 'closing'}>
              {browserState === 'closing' ? 'Closing' : 'Close Browser'}
            </Button>
          </div>
          <div className="button-row">
            <Button variant="secondary" onClick={refreshProxyCaStatus} disabled={proxyCaState === 'loading'}>{proxyCaState === 'loading' ? 'Checking' : 'Check CA'}</Button>
            <Button variant="secondary" onClick={generateProxyCa} disabled={proxyCaState === 'generating'}>{proxyCaState === 'generating' ? 'Generating' : 'Generate CA'}</Button>
            <Button variant="ghost" onClick={downloadProxyCa} disabled={!proxyCaStatus?.generated}>Download CA</Button>
          </div>
          <div className="leaf-cert-row">
            <input value={leafHost} onChange={(event) => setLeafHost(event.target.value)} placeholder="authorized-api-host.test" />
            <Button variant="secondary" onClick={handleGenerateLeaf} disabled={!proxyCaStatus?.generated || !leafHost.trim() || leafState === 'generating'}>
              {leafState === 'generating' ? 'Generating' : 'Host Cert'}
            </Button>
          </div>
          {leafStatus && (
            <code className="leaf-status">{leafStatus.generated ? leafStatus.hostname : leafStatus.warning || 'not generated'}</code>
          )}
        </Card>
      </div>

      <div className="manual-tool-rail">
        {[
          ['proxy', 'account_tree', 'Proxy History', 'Inspect intercepted traffic'],
          ['repeater', 'repeat', 'Repeater', 'Replay and diff responses'],
          ['intruder', 'target', 'Intruder', 'Cluster payload results'],
          ['decoder', 'data_object', 'Decoder', 'Transform encoded data'],
          ['comparer', 'difference', 'Comparer', 'Compare response deltas'],
        ].map(([id, icon, title, detail]) => (
          <button type="button" key={id} onClick={() => onNavigate(id)}>
            <span className="material-symbols-outlined">{icon}</span>
            <strong>{title}</strong>
            <em>{detail}</em>
          </button>
        ))}
      </div>
    </div>
  );
}
