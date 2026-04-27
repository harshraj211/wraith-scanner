import React from 'react';
import StatusPill from '../ui/StatusPill';

export default function ScanStatusStrip({ scanId, status, requests, findings, imports }) {
  return (
    <div className="scan-status-strip">
      <div><span>Scan ID</span><strong>{scanId || 'none'}</strong></div>
      <div><span>Status</span><StatusPill status={status || 'idle'} /></div>
      <div><span>Requests</span><strong>{requests ?? 0}</strong></div>
      <div><span>Findings</span><strong>{findings ?? 0}</strong></div>
      <div><span>Imports</span><strong>{imports ?? 0}</strong></div>
    </div>
  );
}
