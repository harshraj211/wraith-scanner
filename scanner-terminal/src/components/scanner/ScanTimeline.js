import React from 'react';
import Card from '../ui/Card';

export default function ScanTimeline({ events = [] }) {
  const visible = events.length ? events.slice(-8).reverse() : [
    { type: 'info', message: 'Waiting for scan events.' },
  ];
  return (
    <Card title="Scan Timeline" eyebrow="Events">
      <div className="scan-timeline">
        {visible.map((event, index) => (
          <div key={`${event.type}-${index}`}>
            <span />
            <strong>{event.type || 'info'}</strong>
            <p>{event.message || JSON.stringify(event)}</p>
          </div>
        ))}
      </div>
    </Card>
  );
}
