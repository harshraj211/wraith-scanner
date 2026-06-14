import React from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';

export default function ReportExportPanel({ scanId, scanStatus, onDownloadPdf, onDownloadJson }) {
  const reportReady = String(scanStatus?.status || '').toLowerCase() === 'completed';
  const disabled = !scanId || !reportReady;
  const disabledTitle = !scanId
    ? 'Run or select a scan before downloading reports.'
    : 'Report generation is still running.';

  return (
    <Card title="Report Exports" eyebrow="Deliverables">
      <div className="report-export-grid">
        <div>
          <span className="material-symbols-outlined">picture_as_pdf</span>
          <strong>Executive PDF</strong>
          <p>Client-ready report with findings and evidence.</p>
          <Button variant="secondary" disabled={disabled} title={disabled ? disabledTitle : 'Download PDF report'} onClick={onDownloadPdf}>Download PDF</Button>
        </div>
        <div>
          <span className="material-symbols-outlined">data_object</span>
          <strong>Canonical JSON</strong>
          <p>Machine-readable scan, corpus, and proof data.</p>
          <Button disabled={disabled} title={disabled ? disabledTitle : 'Download JSON report'} onClick={onDownloadJson}>Download JSON</Button>
        </div>
      </div>
    </Card>
  );
}
