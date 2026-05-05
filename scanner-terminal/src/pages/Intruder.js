import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import DataTable from '../components/ui/DataTable';
import RequestResponseViewer from '../components/scanner/RequestResponseViewer';
import { ManualRequestFields } from './Repeater';

export default function Intruder({
  manualRequest,
  updateManualRequest,
  intruderConfig,
  updateIntruderConfig,
  runIntruder,
  stopIntruder,
  intruderState,
  intruderResults,
  selectedIntruderResult,
  selectedIntruderResultId,
  selectIntruderResult,
  sendIntruderResultToRepeater,
}) {
  const running = ['running', 'stopping'].includes(intruderState);
  return (
    <div className="page-fill">
      <PageHeader
        eyebrow="Manual"
        title="Payload Runner"
        description="Capped safe-mode payload runner with response clustering."
        actions={(
          <>
            <Button variant="secondary" onClick={stopIntruder} disabled={!running}>Stop</Button>
            <Button onClick={runIntruder} disabled={running}>{running ? 'Running' : 'Run attack'}</Button>
          </>
        )}
      />
      <div className="intruder-layout">
        <Card title="Request Template" eyebrow="Intruder">
          <ManualRequestFields request={manualRequest} updateRequest={updateManualRequest} />
          <div className="form-grid">
            <label className="field"><span>Payload marker</span><input value={intruderConfig.marker} onChange={(event) => updateIntruderConfig('marker', event.target.value)} /></label>
            <label className="field"><span>Delay ms</span><input value={intruderConfig.delayMs} onChange={(event) => updateIntruderConfig('delayMs', event.target.value)} /></label>
            <label className="field"><span>Max requests</span><input value={intruderConfig.maxRequests} onChange={(event) => updateIntruderConfig('maxRequests', event.target.value)} /></label>
            <label className="field"><span>Grep match</span><input placeholder="text expected in response" value={intruderConfig.matchText} onChange={(event) => updateIntruderConfig('matchText', event.target.value)} /></label>
            <label className="field wide"><span>Extract regex</span><input placeholder="e.g. token=([A-Za-z0-9._-]+)" value={intruderConfig.extractRegex} onChange={(event) => updateIntruderConfig('extractRegex', event.target.value)} /></label>
            <label className="field wide"><span>Payloads</span><textarea value={intruderConfig.payloads} onChange={(event) => updateIntruderConfig('payloads', event.target.value)} /></label>
          </div>
        </Card>
        <Card
          title="Results"
          eyebrow={intruderState}
          actions={<Button variant="secondary" disabled={!selectedIntruderResult?.exchange} onClick={() => sendIntruderResultToRepeater(selectedIntruderResult)}>Send to Repeater</Button>}
        >
          <DataTable
            columns={[
              { key: 'payload', label: 'Payload', width: 'minmax(180px, 1fr)' },
              { key: 'status', label: 'Status', width: '82px' },
              { key: 'length', label: 'Length', width: '82px' },
              { key: 'timeMs', label: 'Time', width: '82px' },
              { key: 'matched', label: 'Match', width: '82px', render: (row) => row.matched ? 'yes' : '-' },
              { key: 'extract', label: 'Extract', width: 'minmax(120px, 180px)' },
              { key: 'cluster', label: 'Cluster', width: 'minmax(160px, 1fr)' },
            ]}
            rows={intruderResults}
            rowKey="resultId"
            onRowClick={(row) => selectIntruderResult(row.resultId)}
            emptyTitle={selectedIntruderResultId ? 'No matching result' : 'No Intruder results yet'}
          />
          <RequestResponseViewer exchange={selectedIntruderResult?.exchange} />
        </Card>
      </div>
    </div>
  );
}
