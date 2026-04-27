import React from 'react';

const navItems = [
  ['overview', 'dashboard', 'Overview'],
  ['automated-setup', 'radar', 'Automated Scans'],
  ['manual', 'biotech', 'Manual Testing'],
  ['repository', 'source', 'Repository Scan'],
  ['evidence', 'storage', 'Evidence Corpus'],
  ['findings', 'gavel', 'Findings'],
  ['proof', 'verified_user', 'Proof Mode'],
  ['reports', 'assessment', 'Reports'],
  ['settings', 'settings', 'Settings'],
];

function isActive(activePage, item) {
  if (item === 'automated-setup') return ['automated-setup', 'automated-workspace'].includes(activePage);
  if (item === 'manual') return ['manual', 'proxy', 'repeater', 'intruder', 'decoder'].includes(activePage);
  return activePage === item;
}

export default function Sidebar({ activePage, onNavigate, latestScanId }) {
  return (
    <aside className="app-sidebar">
      <button className="sidebar-brand" onClick={() => onNavigate('overview')}>
        <span className="brand-glyph">W</span>
        <span>
          <strong>WRAITH</strong>
          <em>Precision Stealth</em>
        </span>
      </button>

      <nav className="sidebar-nav" aria-label="Wraith navigation">
        {navItems.map(([id, icon, label]) => (
          <button
            className={isActive(activePage, id) ? 'sidebar-link active' : 'sidebar-link'}
            key={id}
            onClick={() => onNavigate(id)}
          >
            <span className="material-symbols-outlined">{icon}</span>
            <span>{label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <span className="status-dot" />
        <span>{latestScanId ? `scan ${latestScanId}` : 'local corpus ready'}</span>
      </div>
    </aside>
  );
}
