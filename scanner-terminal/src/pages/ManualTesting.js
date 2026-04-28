import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import MetricCard from '../components/ui/MetricCard';

export default function ManualTesting({
  onNavigate,
  proxyStatus,
  corpusRequests,
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
        description="Proxy capture, Repeater, Intruder, Decoder, and report evidence workflows."
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
        <MetricCard label="Tools" value="4" detail="proxy/repeater/intruder/decoder" tone="blue" />
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
      <div className="tool-grid">
        {[
          ['proxy', 'HTTP Proxy', 'Capture, pause, forward, drop, and edit requests.'],
          ['repeater', 'Repeater', 'Edit and replay individual requests with response diffs.'],
          ['intruder', 'Intruder', 'Run capped payload lists with clustering and safe-mode controls.'],
          ['decoder', 'Decoder', 'Chain URL/Base64/JWT/JSON transformations.'],
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
