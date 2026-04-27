import React from 'react';

export default function Card({ children, title, eyebrow, actions, className = '' }) {
  return (
    <section className={`card ${className}`.trim()}>
      {(title || eyebrow || actions) && (
        <div className="card-header">
          <div>
            {eyebrow && <span className="eyebrow">{eyebrow}</span>}
            {title && <h2>{title}</h2>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}
