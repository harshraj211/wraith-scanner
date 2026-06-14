import React, { useEffect, useMemo, useRef } from 'react';
import Card from './Card';

export default function TerminalPanel({ events = [], terminalRef }) {
  const localRef = useRef(null);
  const panelRef = terminalRef || localRef;
  const visibleEvents = useMemo(() => (
    events.length ? events.slice(0, 80).reverse() : []
  ), [events]);

  useEffect(() => {
    if (panelRef?.current) {
      panelRef.current.scrollTop = panelRef.current.scrollHeight;
    }
  }, [panelRef, visibleEvents]);

  return (
    <Card title="Execution Output" eyebrow="Terminal" className="terminal-card">
      <div className="terminal-panel" ref={panelRef}>
        {events.length === 0 ? (
          <>
            <div><span>[info]</span> Wraith workbench ready.</div>
            <div><span>[hint]</span> Start a scan or load corpus evidence.</div>
          </>
        ) : visibleEvents.map((event, index) => (
          <div key={`${event.type}-${index}`}>
            <span>[{event.type || 'info'}]</span> {event.message || JSON.stringify(event)}
          </div>
        ))}
        <div className="terminal-cursor"><strong>wraith &gt;</strong><i /></div>
      </div>
    </Card>
  );
}
