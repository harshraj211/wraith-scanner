import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import TerminalPanel from '../components/ui/TerminalPanel';
import ReportExportPanel from '../components/scanner/ReportExportPanel';
import ScanTimeline from '../components/scanner/ScanTimeline';

export default function Reports({ latestScanId, progressEvents, onDownloadPdf, onDownloadJson }) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Reports"
        title="Reporting & Logs"
        description="Export client-ready deliverables and inspect execution trails."
      />
      <div className="reports-grid">
        <ReportExportPanel scanId={latestScanId} onDownloadPdf={onDownloadPdf} onDownloadJson={onDownloadJson} />
        <ScanTimeline events={progressEvents} />
        <TerminalPanel events={progressEvents} />
      </div>
    </div>
  );
}
