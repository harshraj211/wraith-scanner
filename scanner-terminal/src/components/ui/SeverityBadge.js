import React from 'react';

export default function SeverityBadge({ severity }) {
  const value = String(severity || 'info').toLowerCase();
  return <span className={`severity severity-${value}`}>{value}</span>;
}
