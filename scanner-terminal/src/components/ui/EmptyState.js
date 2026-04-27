import React from 'react';

export default function EmptyState({ title = 'No data yet', body = 'Run or refresh a scan to populate this view.' }) {
  return (
    <div className="empty-state">
      <span className="material-symbols-outlined">radar</span>
      <strong>{title}</strong>
      <p>{body}</p>
    </div>
  );
}
