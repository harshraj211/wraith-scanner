import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';

export default function ModeSelect({ onNavigate }) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Launch"
        title="Start Wraith"
        description="Choose the workflow you want to run."
      />
      <div className="mode-grid">
        <Card title="Automated Scan" eyebrow="VA Pipeline">
          <p>Run DAST, API imports, SAST correlation, corpus capture, and reporting.</p>
          <Button onClick={() => onNavigate('automated-workspace')}>Open Automated</Button>
        </Card>
        <Card title="Manual Testing" eyebrow="Workbench">
          <p>Capture traffic, replay requests, fuzz payload positions, decode values, and collect evidence.</p>
          <Button variant="secondary" onClick={() => onNavigate('manual')}>Open Manual</Button>
        </Card>
        <Card title="Repository Scan" eyebrow="SAST">
          <p>Scan GitHub repositories and local source workflows with Semgrep and Wraith taint analysis.</p>
          <Button variant="secondary" onClick={() => onNavigate('repository')}>Open Repository</Button>
        </Card>
      </div>
    </div>
  );
}
