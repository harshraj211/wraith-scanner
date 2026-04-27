import React from 'react';

export default function Tabs({ tabs, active, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((tab) => {
        const id = Array.isArray(tab) ? tab[0] : tab.id;
        const label = Array.isArray(tab) ? tab[1] : tab.label;
        return (
          <button
            role="tab"
            aria-selected={active === id}
            className={active === id ? 'active' : ''}
            key={id}
            onClick={() => onChange(id)}
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}
