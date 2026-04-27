import React from 'react';

const order = ['critical', 'high', 'medium', 'low', 'info'];

export default function SeveritySummary({ counts = {} }) {
  const total = order.reduce((sum, key) => sum + Number(counts[key] || 0), 0) || 1;
  return (
    <div className="severity-summary">
      {order.map((key) => (
        <div key={key}>
          <span>{key}</span>
          <strong>{counts[key] || 0}</strong>
          <em><i style={{ width: `${(Number(counts[key] || 0) / total) * 100}%` }} /></em>
        </div>
      ))}
    </div>
  );
}
