import React from 'react';

export default function MetricCard({ label, value, detail, tone = 'cyan' }) {
  return (
    <div className={`metric-card metric-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {detail && <em>{detail}</em>}
    </div>
  );
}
