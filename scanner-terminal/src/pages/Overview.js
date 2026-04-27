import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import MetricCard from '../components/ui/MetricCard';

export default function Overview({ onNavigate, stats }) {
  return (
    <div className="page-stack overview-page">
      <section className="hero-grid">
        <div className="hero-copy">
          <span className="eyebrow">VA + Proof Scanner</span>
          <h1>Wraith v4</h1>
          <p>
            Evidence-first vulnerability assessment for SPAs, APIs, repositories,
            and safe proof workflows. Built for defensible AppSec evidence, not noise.
          </p>
          <div className="button-row">
            <Button size="lg" onClick={() => onNavigate('mode')}>Start Scan</Button>
            <Button size="lg" variant="secondary" onClick={() => onNavigate('manual')}>Manual Workbench</Button>
          </div>
        </div>
        <div className="radar-card">
          <div className="radar-screen">
            <span className="radar-line" />
            <span className="radar-cross-x" />
            <span className="radar-cross-y" />
            <strong>SCAN_ID::{stats?.scanId || 'READY'}</strong>
          </div>
        </div>
      </section>

      <div className="metric-grid five">
        <MetricCard label="DAST Modules" value="18" detail="OWASP, API, SPA" />
        <MetricCard label="API Importers" value="4" detail="OpenAPI/Postman/HAR/GraphQL" />
        <MetricCard label="Proof Modes" value="3" detail="safe / intrusive / lab" tone="emerald" />
        <MetricCard label="Evidence Store" value={stats?.requests || 0} detail="corpus requests" tone="blue" />
        <MetricCard label="Exports" value="PDF/JSON" detail="report-ready" tone="amber" />
      </div>

      <PageHeader eyebrow="Core Capabilities" title="Modern AppSec Workflows" />
      <div className="capability-grid">
        {[
          ['radar', 'DAST', 'Async scanning with response intelligence and OOB correlation.'],
          ['code_blocks', 'SAST', 'Semgrep, taint analysis, secrets, and dependency CVEs.'],
          ['travel_explore', 'SPA Exploration', 'Playwright-driven discovery and storage-state mutation.'],
          ['storage', 'Evidence Corpus', 'Durable request, response, finding, and proof artifacts.'],
          ['verified_user', 'Proof Mode', 'Bounded non-destructive verification of high-confidence issues.'],
          ['assessment', 'Reports', 'PDF and canonical JSON deliverables with redaction.'],
        ].map(([icon, title, body]) => (
          <Card key={title} className="capability-card">
            <span className="material-symbols-outlined">{icon}</span>
            <h2>{title}</h2>
            <p>{body}</p>
          </Card>
        ))}
      </div>
    </div>
  );
}
