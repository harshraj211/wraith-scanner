import React, { useMemo, useState } from 'react';
import Button from '../ui/Button';
import StatusPill from '../ui/StatusPill';
import wraithMark from '../../assets/wraith-signal-phantom-mark.png';

const searchTargets = [
  ['overview', 'Overview', 'dashboard home status'],
  ['automated-setup', 'Scan Setup', 'automated dast target configure launch'],
  ['automated-workspace', 'Cockpit', 'scan workspace live status results'],
  ['findings', 'Findings', 'vulnerabilities issues risk proof'],
  ['evidence', 'Evidence Corpus', 'requests responses corpus traffic'],
  ['manual', 'Manual Testing', 'proxy repeater intruder decoder comparer'],
  ['proxy', 'Proxy History', 'intercept history passive'],
  ['repeater', 'Repeater', 'replay request'],
  ['intruder', 'Intruder', 'fuzz payloads'],
  ['decoder', 'Decoder', 'encode decode'],
  ['comparer', 'Comparer', 'diff compare'],
  ['repository', 'Repository Scan', 'sast semgrep github source'],
  ['nuclei', 'Nuclei & CVE', 'templates cve intelligence'],
  ['proof', 'Proof Mode', 'verification authorization matrix'],
  ['reports', 'Reports', 'pdf json export'],
  ['settings', 'Settings', 'configuration safety api'],
];

export default function Topbar({ socketState, onNavigate, onStartScan, onOpenMobileNav }) {
  const [query, setQuery] = useState('');
  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return [];
    return searchTargets
      .filter(([, label, keywords]) => `${label} ${keywords}`.toLowerCase().includes(needle))
      .slice(0, 5);
  }, [query]);

  const chooseTarget = (page) => {
    onNavigate(page);
    setQuery('');
  };

  const submitSearch = (event) => {
    event.preventDefault();
    if (matches[0]) chooseTarget(matches[0][0]);
  };

  return (
    <header className="app-topbar">
      <button className="mobile-menu-button" type="button" aria-label="Open navigation" onClick={onOpenMobileNav}>
        <span className="material-symbols-outlined">menu</span>
      </button>
      <span className="topbar-brand" aria-label="WRAITH">
        <img src={wraithMark} alt="" />
        <strong>WRAITH</strong>
      </span>
      <form className="topbar-search" onSubmit={submitSearch}>
        <span>&gt;_</span>
        <input
          aria-label="Search Wraith pages"
          placeholder="Jump to findings, repeater, reports..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        {matches.length > 0 && (
          <div className="topbar-search-results">
            {matches.map(([page, label]) => (
              <button type="button" key={page} onClick={() => chooseTarget(page)}>
                {label}
              </button>
            ))}
          </div>
        )}
      </form>
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
