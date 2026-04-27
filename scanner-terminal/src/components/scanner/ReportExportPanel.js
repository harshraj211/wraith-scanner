import React from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';

export default function ReportExportPanel({ scanId, onDownloadPdf, onDownloadJson }) {
  return (
    <Card title="Report Exports" eyebrow="Deliverables">
      <div className="report-export-grid">
        <div>
          <span className="material-symbols-outlined">picture_as_pdf</span>
          <strong>Executive PDF</strong>
          <p>Client-ready report with findings and evidence.</p>
          <Button variant="secondary" disabled={!scanId} onClick={onDownloadPdf}>Download PDF</Button>
        </div>
        <div>
          <span className="material-symbols-outlined">data_object</span>
          <strong>Canonical JSON</strong>
          <p>Machine-readable scan, corpus, and proof data.</p>
          <Button disabled={!scanId} onClick={onDownloadJson}>Download JSON</Button>
        </div>
      </div>
    </Card>
  );
}
