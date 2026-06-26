import React, { useEffect, useState } from 'react';
import MetricCard from '../components/ui/MetricCard';
import SeveritySummary from '../components/scanner/SeveritySummary';
import '../App.css';

const RiskPostureDashboard = () => {
  const [stats, setStats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    totalAssets: 0,
  });

  useEffect(() => {
    setStats({ critical: 4, high: 12, medium: 28, low: 45, totalAssets: 15 });
  }, []);

  return (
    <div className="p-8 bg-gray-900 min-h-screen text-white">
      <h1 className="text-3xl font-bold mb-8 border-b border-gray-700 pb-4">
        Executive Risk Posture
      </h1>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <MetricCard title="Total Assets Scanned" value={stats.totalAssets} icon="🌐" />
        <MetricCard title="Critical Vulnerabilities" value={stats.critical} icon="🔥" alert={stats.critical > 0} />
        <MetricCard title="High Vulnerabilities" value={stats.high} icon="⚠️" />
        <MetricCard title="Remediation SLA Breaches" value="3" icon="⏳" alert={true} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
          <h2 className="text-xl font-semibold mb-4 text-gray-300">Vulnerability Breakdown</h2>
          <SeveritySummary stats={stats} />
        </div>

        <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
          <h2 className="text-xl font-semibold mb-4 text-gray-300">Compliance Score (OWASP Top 10)</h2>
          <div className="w-full bg-gray-700 rounded-full h-2.5 mb-4">
            <div className="bg-red-500 h-2.5 rounded-full" style={{ width: '45%' }} />
          </div>
          <p className="text-sm text-gray-400">
            Currently failing 4/10 OWASP categories. Immediate action required on A01: Broken Access Control.
          </p>
        </div>
      </div>
    </div>
  );
};

export default RiskPostureDashboard;
