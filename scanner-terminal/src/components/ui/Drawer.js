import React from 'react';

export default function Drawer({ open, title, onClose, children, actions }) {
  if (!open) return null;
  return (
    <aside className="drawer">
      <div className="drawer-header">
        <h2>{title}</h2>
        <button className="icon-button" onClick={onClose} aria-label="Close drawer">
          <span className="material-symbols-outlined">close</span>
        </button>
      </div>
      <div className="drawer-body">{children}</div>
      {actions && <div className="drawer-actions">{actions}</div>}
    </aside>
  );
}
