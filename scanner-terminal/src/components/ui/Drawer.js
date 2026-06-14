import React from 'react';

export default function Drawer({ open, title, onClose, children, actions }) {
  if (!open) return null;
  const titleId = `drawer-${String(title || 'panel').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
  return (
    <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby={titleId}>
      <div className="drawer-header">
        <h2 id={titleId}>{title}</h2>
        <button className="icon-button" onClick={onClose} aria-label="Close drawer">
          <span className="material-symbols-outlined">close</span>
        </button>
      </div>
      <div className="drawer-body">{children}</div>
      {actions && <div className="drawer-actions">{actions}</div>}
    </aside>
  );
}
