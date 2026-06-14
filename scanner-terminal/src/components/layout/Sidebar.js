import React from 'react';
import wraithMark from '../../assets/wraith-signal-phantom-mark.png';

const navGroups = [
  {
    label: 'Automated',
    items: [
      ['overview', 'dashboard', 'Overview'],
      ['automated-setup', 'radar', 'Scan Setup'],
      ['automated-workspace', 'space_dashboard', 'Cockpit'],
      ['repository', 'source', 'Repository Scan'],
      ['nuclei', 'hub', 'Nuclei & CVE'],
    ],
  },
  {
    label: 'Manual Testing',
    items: [
      ['manual', 'biotech', 'Workbench'],
      ['proxy', 'account_tree', 'Proxy History'],
      ['repeater', 'repeat', 'Repeater'],
      ['intruder', 'target', 'Intruder'],
      ['decoder', 'data_object', 'Decoder'],
      ['comparer', 'difference', 'Comparer'],
    ],
  },
  {
    label: 'Analysis',
    items: [
      ['evidence', 'storage', 'Evidence Corpus'],
      ['findings', 'gavel', 'Findings'],
      ['proof', 'verified_user', 'Proof Mode'],
      ['reports', 'assessment', 'Reports'],
    ],
  },
  {
    label: 'System',
    items: [
      ['settings', 'settings', 'Settings'],
    ],
  },
];

function isActive(activePage, item) {
  return activePage === item;
}

export default function Sidebar({ activePage, onNavigate, latestScanId, className = '', onClose }) {
  return (
    <aside className={`app-sidebar ${className}`.trim()}>
      <button className="sidebar-brand" onClick={() => onNavigate('overview')}>
        <span className="brand-mark-wrap" aria-hidden="true">
          <img className="brand-mark" src={wraithMark} alt="" />
        </span>
        <span>
          <strong>WRAITH</strong>
          <em>Vulnerability Scanner</em>
        </span>
      </button>
      {onClose && (
        <button className="icon-button sidebar-close" type="button" aria-label="Close navigation" onClick={onClose}>
          <span className="material-symbols-outlined">close</span>
        </button>
      )}

      <nav className="sidebar-nav" aria-label="Wraith navigation">
        {navGroups.map((group) => (
          <div className="sidebar-group" key={group.label}>
            <span className="sidebar-group-label">{group.label}</span>
            {group.items.map(([id, icon, label]) => (
              <button
                className={isActive(activePage, id) ? 'sidebar-link active' : 'sidebar-link'}
                key={id}
                onClick={() => onNavigate(id)}
              >
                <span className="material-symbols-outlined">{icon}</span>
                <span>{label}</span>
              </button>
            ))}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <span className="status-dot" />
        <span>{latestScanId ? `scan ${latestScanId}` : 'local corpus ready'}</span>
      </div>
    </aside>
  );
}
