import React from 'react';

export default function SplitPane({ left, right, className = '' }) {
  return (
    <div className={`split-pane ${className}`.trim()}>
      <div>{left}</div>
      <div>{right}</div>
    </div>
  );
}
