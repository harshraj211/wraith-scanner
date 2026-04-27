import React from 'react';
import Sidebar from './Sidebar';
import Topbar from './Topbar';

export default function AppShell({
  activePage,
  onNavigate,
  socketState,
  latestScanId,
  onStartScan,
  children,
}) {
  return (
    <div className="wraith-shell">
      <Sidebar activePage={activePage} onNavigate={onNavigate} latestScanId={latestScanId} />
      <div className="wraith-main">
        <Topbar
          socketState={socketState}
          onNavigate={onNavigate}
          onStartScan={onStartScan}
        />
        <main className="wraith-canvas">{children}</main>
      </div>
    </div>
  );
}
