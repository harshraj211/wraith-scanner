import React from 'react';

const workflowTabs = [
  ['automated-setup', 'Scan Setup'],
  ['automated-workspace', 'Cockpit'],
  ['repository', 'Repository Scan'],
  ['nuclei', 'Nuclei & CVE'],
];

export default function WorkflowHero({
  icon = 'radar',
  eyebrow = 'Automated',
  title,
  description,
  active,
  onNavigate,
  actions,
}) {
  return (
    <section className="workflow-hero">
      <div className="workflow-title">
        <span className="workflow-icon material-symbols-outlined">{icon}</span>
        <div>
          <em>{eyebrow}</em>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
      </div>
      <div className="workflow-tabs">
        {workflowTabs.map(([id, label]) => (
          <button
            className={active === id ? 'active' : ''}
            type="button"
            key={id}
            onClick={() => onNavigate?.(id)}
          >
            {label}
          </button>
        ))}
      </div>
      {actions && <div className="workflow-hero-actions">{actions}</div>}
    </section>
  );
}
