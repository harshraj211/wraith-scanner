import React, { useEffect, useState } from 'react';
import axios from 'axios';
import PageHeader from '../components/layout/PageHeader';
import TerminalPanel from '../components/ui/TerminalPanel';
import ReportExportPanel from '../components/scanner/ReportExportPanel';
import ScanTimeline from '../components/scanner/ScanTimeline';

export default function Reports({ latestScanId, scanStatus, progressEvents, onDownloadPdf, onDownloadJson }) {
  const [compliance, setCompliance] = useState(null);

  useEffect(() => {
    let mounted = true;
    axios.get('/api/v1/reports/compliance')
      .then((res) => {
        if (mounted) setCompliance(res.data);
      })
      .catch(() => {
        if (mounted) setCompliance(null);
      });
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <div className="page-stack lab-page reports-page">
      <PageHeader
        eyebrow="Reports"
        title="Reporting & Logs"
        description="Export client-ready deliverables and inspect execution trails."
      />
      <div className="reports-grid">
        <ReportExportPanel scanId={latestScanId} scanStatus={scanStatus} onDownloadPdf={onDownloadPdf} onDownloadJson={onDownloadJson} />
        <ComplianceSummary compliance={compliance} />
        <ScanTimeline events={progressEvents} />
        <TerminalPanel events={progressEvents} />
      </div>
    </div>
  );
}

function ComplianceSummary({ compliance }) {
  if (!compliance) {
    return <div className="bg-gray-800 p-6 rounded-lg text-white">Generating Compliance Matrix...</div>;
  }

  return (
    <div className="bg-gray-800 p-6 rounded-lg shadow-lg text-white">
      <h2 className="text-xl font-bold mb-4">Compliance Attestation Report</h2>
      <div className="grid grid-cols-1 gap-4">
        {Object.keys(compliance).map((framework) => (
          <div key={framework} className="border border-gray-700 rounded p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold">{framework.replace(/_/g, ' ')}</h3>
              <span className={compliance[framework]._overall_status === 'PASS' ? 'text-green-400' : 'text-red-400'}>
                {compliance[framework]._overall_status}
              </span>
            </div>
            <div className="space-y-2">
              {Object.entries(compliance[framework]).map(([control, data]) => {
                if (control === '_overall_status') return null;
                return (
                  <div key={control} className="text-sm border-l-2 border-red-500 pl-3">
                    <div>{control}</div>
                    <div className="text-gray-400">{data.findings_count} findings ({data.severity})</div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
