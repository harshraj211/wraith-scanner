import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import MetricCard from '../components/ui/MetricCard';

export default function ManualTesting({
  onNavigate,
  proxyStatus,
  corpusRequests,
  proxyCaStatus,
  proxyCaState,
  refreshProxyCaStatus,
  generateProxyCa,
  downloadProxyCa,
  browserState,
  browserStatus,
  openWraithBrowser,
  closeWraithBrowser,
}) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Manual"
        title="Manual Testing"
        description="Proxy capture, Repeater, Intruder, Decoder, Comparer, and report evidence workflows."
        actions={(
          <>
            <Button variant="secondary" onClick={openWraithBrowser} disabled={browserState === 'opening'}>
              {browserState === 'opening' ? 'Opening...' : 'Open Wraith Browser'}
            </Button>
            <Button onClick={() => onNavigate('proxy')}>Open Proxy</Button>
          </>
        )}
      />
      <div className="metric-grid">
        <MetricCard label="Proxy" value={proxyStatus?.running ? 'Running' : 'Stopped'} tone={proxyStatus?.running ? 'emerald' : 'slate'} />
        <MetricCard label="Browser" value={browserStatus?.running ? 'Open' : 'Closed'} tone={browserStatus?.running ? 'emerald' : 'slate'} />
        <MetricCard label="Captured" value={corpusRequests.length} tone="cyan" />
        <MetricCard label="Local CA" value={proxyCaStatus?.generated ? 'Ready' : 'Missing'} tone={proxyCaStatus?.generated ? 'emerald' : 'amber'} />
        <MetricCard label="Tools" value="5" detail="proxy/repeater/intruder/decoder/comparer" tone="blue" />
      </div>
      <Card title="Controlled Wraith Browser" eyebrow="Capture">
        <p>
          Launch a dedicated headed browser profile through the local Wraith HTTP proxy.
          This captures browser traffic into the request corpus while keeping HTTPS MITM
          behind a later explicit certificate setup step.
        </p>
        <div className="button-row">
          <Button variant="secondary" onClick={openWraithBrowser} disabled={browserState === 'opening'}>
            {browserState === 'opening' ? 'Opening...' : 'Open Through Proxy'}
          </Button>
          <Button variant="ghost" onClick={closeWraithBrowser} disabled={!browserStatus?.running || browserState === 'closing'}>
            {browserState === 'closing' ? 'Closing...' : 'Close Browser'}
          </Button>
          <Button variant="ghost" onClick={() => onNavigate('proxy')}>Proxy History</Button>
        </div>
        <div className="nuclei-asset-card">
          <div>
            <span>Proxy</span>
            <code>{proxyStatus?.running ? `${proxyStatus.host}:${proxyStatus.port}` : 'not listening'}</code>
          </div>
          <div>
            <span>Profile</span>
            <code>{browserStatus?.profile_dir || 'created on launch'}</code>
          </div>
          {browserStatus?.error && (
            <div>
              <span>Error</span>
              <code>{browserStatus.error}</code>
            </div>
          )}
          {browserStatus?.warning && (
            <div>
              <span>Warning</span>
              <code>{browserStatus.warning}</code>
            </div>
          )}
        </div>
      </Card>
      <Card title="HTTPS Interception Prep" eyebrow="Local CA">
        <p>
          Prepare the certificate trust layer for a future scoped HTTPS MITM engine.
          The current proxy still refuses CONNECT interception until that guarded engine is implemented.
        </p>
        <div className="button-row">
          <Button variant="secondary" onClick={refreshProxyCaStatus} disabled={proxyCaState === 'loading'}>{proxyCaState === 'loading' ? 'Checking' : 'Check CA'}</Button>
          <Button onClick={generateProxyCa} disabled={proxyCaState === 'generating'}>{proxyCaState === 'generating' ? 'Generating' : 'Generate CA'}</Button>
          <Button variant="ghost" onClick={downloadProxyCa} disabled={!proxyCaStatus?.generated}>Download CA</Button>
        </div>
        <div className="nuclei-asset-card">
          <div>
            <span>Status</span>
            <code>{proxyCaStatus?.generated ? 'generated' : proxyCaStatus?.warning || 'not generated'}</code>
          </div>
          <div>
            <span>HTTPS MITM</span>
            <code>{proxyCaStatus?.https_interception_enabled ? 'enabled' : 'disabled'}</code>
          </div>
          <div>
            <span>Fingerprint</span>
            <code>{proxyCaStatus?.fingerprint_sha256 || '-'}</code>
          </div>
          <div>
            <span>Valid until</span>
            <code>{proxyCaStatus?.valid_until || '-'}</code>
          </div>
        </div>
      </Card>
      <div className="tool-grid">
        {[
          ['proxy', 'HTTP Proxy', 'Capture, pause, forward, drop, and edit requests.'],
          ['repeater', 'Repeater', 'Edit and replay individual requests with response diffs.'],
          ['intruder', 'Intruder', 'Run capped payload lists with clustering and safe-mode controls.'],
          ['decoder', 'Decoder', 'Chain URL/Base64/JWT/JSON transformations.'],
          ['comparer', 'Comparer', 'Compare response headers, JSON values, body hashes, size, and timing.'],
        ].map(([id, title, body]) => (
          <Card title={title} eyebrow="Manual Tool" key={id}>
            <p>{body}</p>
            <Button variant="secondary" onClick={() => onNavigate(id)}>{title}</Button>
          </Card>
        ))}
      </div>
    </div>
  );
}
