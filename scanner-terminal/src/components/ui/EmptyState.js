import React from 'react';

export default function EmptyState({ icon = 'radar', title = 'No data yet', body = 'Run or refresh a scan to populate this view.' }) {
  return (
    <div className="empty-state">
      <span className="material-symbols-outlined">{icon}</span>
      <strong>{title}</strong>
      <p>{body}</p>
    </div>
  );
}
