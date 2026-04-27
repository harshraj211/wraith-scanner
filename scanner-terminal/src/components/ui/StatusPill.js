import React from 'react';

export default function StatusPill({ status }) {
  const value = String(status || 'idle').toLowerCase();
  return (
    <span className={`status-pill status-${value}`}>
      <span />
      {value}
    </span>
  );
}
