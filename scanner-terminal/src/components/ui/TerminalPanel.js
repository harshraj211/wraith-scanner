import React from 'react';
import Card from './Card';

export default function TerminalPanel({ events = [], terminalRef }) {
  return (
    <Card title="Execution Output" eyebrow="Terminal" className="terminal-card">
      <div className="terminal-panel" ref={terminalRef}>
        {events.length === 0 ? (
          <>
            <div><span>[info]</span> Wraith workbench ready.</div>
            <div><span>[hint]</span> Start a scan or load corpus evidence.</div>
          </>
        ) : events.slice(-80).map((event, index) => (
          <div key={`${event.type}-${index}`}>
            <span>[{event.type || 'info'}]</span> {event.message || JSON.stringify(event)}
          </div>
        ))}
        <div className="terminal-cursor"><strong>wraith &gt;</strong><i /></div>
      </div>
    </Card>
  );
}
