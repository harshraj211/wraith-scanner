import React, { useState } from 'react';
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
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const isCockpit = activePage === 'automated-workspace';
  const navigateFromMobile = (page) => {
    onNavigate(page);
    setMobileNavOpen(false);
  };

  return (
    <div className={isCockpit ? 'wraith-shell cockpit-shell-mode' : 'wraith-shell'}>
      <Sidebar activePage={activePage} onNavigate={onNavigate} latestScanId={latestScanId} />
      {mobileNavOpen && (
        <div className="mobile-nav-layer">
          <button className="mobile-nav-backdrop" type="button" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />
          <Sidebar
            activePage={activePage}
            onNavigate={navigateFromMobile}
            latestScanId={latestScanId}
            className="mobile-sidebar"
            onClose={() => setMobileNavOpen(false)}
          />
        </div>
      )}
      <div className="wraith-main">
        <Topbar
          socketState={socketState}
          onNavigate={onNavigate}
          onStartScan={onStartScan}
          onOpenMobileNav={() => setMobileNavOpen(true)}
        />
        <main className="wraith-canvas">{children}</main>
      </div>
    </div>
  );
}
