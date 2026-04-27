import React from 'react';
import Button from '../ui/Button';
import StatusPill from '../ui/StatusPill';

export default function Topbar({ socketState, onNavigate, onStartScan }) {
  return (
    <header className="app-topbar">
      <div className="topbar-search">
        <span>&gt;_</span>
        <input aria-label="Search Wraith" placeholder="Search targets, findings, requests, evidence..." />
      </div>
      <div className="topbar-actions">
        <StatusPill status={socketState || 'offline'} />
        <button className="icon-button" title="Corpus" onClick={() => onNavigate('evidence')}>
          <span className="material-symbols-outlined">dns</span>
        </button>
        <button className="icon-button" title="Reports" onClick={() => onNavigate('reports')}>
          <span className="material-symbols-outlined">notifications</span>
        </button>
        <Button onClick={onStartScan}>Start Scan</Button>
      </div>
    </header>
  );
}
