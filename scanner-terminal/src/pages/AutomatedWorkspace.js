import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import MetricCard from '../components/ui/MetricCard';
import TerminalPanel from '../components/ui/TerminalPanel';
import ScanStatusStrip from '../components/scanner/ScanStatusStrip';
import ScanTimeline from '../components/scanner/ScanTimeline';
import SeveritySummary from '../components/scanner/SeveritySummary';

export default function AutomatedWorkspace({
  scanStatus,
  latestScanId,
  dashboard,
  progressEvents,
  corpusRequests,
  refreshStatus,
  submitScan,
  onNavigate,
}) {
  const counts = dashboard?.severityCounts || {};
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Automated Workspace"
        title={scanStatus?.url || scanStatus?.target || 'Risk Dashboard'}
        description="Live scan status, attack surface, findings, evidence, and report actions."
        actions={(
          <>
            <Button variant="secondary" onClick={refreshStatus} disabled={!latestScanId}>Refresh</Button>
            <Button onClick={submitScan}>Scan again</Button>
          </>
        )}
      />
      <ScanStatusStrip
        scanId={latestScanId}
        status={scanStatus?.status || 'idle'}
        requests={corpusRequests.length}
        findings={dashboard?.totalFindings || 0}
        imports={dashboard?.importCount || 0}
      />
      <div className="workspace-tabs">
        <button onClick={() => onNavigate('automated-workspace')}>Overview</button>
        <button onClick={() => onNavigate('findings')}>Findings</button>
        <button onClick={() => onNavigate('evidence')}>Scanned URLs</button>
        <button onClick={() => onNavigate('automated-setup')}>Scan details</button>
        <button onClick={() => onNavigate('reports')}>Reporting & logs</button>
      </div>
      <div className="metric-grid">
        <MetricCard label="Total Findings" value={dashboard?.totalFindings || 0} tone="red" />
        <MetricCard label="Confirmed" value={dashboard?.confirmed || 0} tone="emerald" />
        <MetricCard label="Requests" value={corpusRequests.length} tone="cyan" />
        <MetricCard label="Imports" value={dashboard?.importCount || 0} tone="amber" />
      </div>
      <div className="dashboard-grid">
        <Card title="Severity Summary" eyebrow="Risk">
          <SeveritySummary counts={counts} />
        </Card>
        <Card title="Execution Pipeline" eyebrow="Run State">
          <div className="pipeline">
            <span className="complete">Discovery</span>
            <span className="active">Fuzzing</span>
            <span>Proofing</span>
            <span>Reporting</span>
          </div>
        </Card>
        <ScanTimeline events={progressEvents} />
        <TerminalPanel events={progressEvents} />
      </div>
    </div>
  );
}
