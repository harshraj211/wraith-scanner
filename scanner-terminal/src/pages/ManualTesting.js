import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import MetricCard from '../components/ui/MetricCard';

export default function ManualTesting({ onNavigate, proxyStatus, corpusRequests }) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Manual"
        title="Manual Testing"
        description="Proxy capture, Repeater, Intruder, Decoder, and report evidence workflows."
        actions={<Button onClick={() => onNavigate('proxy')}>Open Proxy</Button>}
      />
      <div className="metric-grid">
        <MetricCard label="Proxy" value={proxyStatus?.running ? 'Running' : 'Stopped'} tone={proxyStatus?.running ? 'emerald' : 'slate'} />
        <MetricCard label="Captured" value={corpusRequests.length} tone="cyan" />
        <MetricCard label="Tools" value="4" detail="proxy/repeater/intruder/decoder" tone="blue" />
      </div>
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
