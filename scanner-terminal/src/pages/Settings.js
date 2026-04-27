import React from 'react';
import PageHeader from '../components/layout/PageHeader';
import Card from '../components/ui/Card';

export default function Settings() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Settings" title="Settings" description="Local workbench configuration and safety defaults." />
      <div className="settings-grid">
        <Card title="Safety Defaults" eyebrow="Policy">
          <div className="summary-list">
            <div><span>Default mode</span><strong>safe</strong></div>
            <div><span>Intrusive approval</span><strong>required</strong></div>
            <div><span>LLM payload execution</span><strong>disabled</strong></div>
          </div>
        </Card>
        <Card title="Backend" eyebrow="API">
          <div className="summary-list">
            <div><span>API URL</span><strong>{process.env.REACT_APP_API_URL || 'http://127.0.0.1:5001'}</strong></div>
            <div><span>Corpus</span><strong>SQLite</strong></div>
          </div>
        </Card>
      </div>
    </div>
  );
}
