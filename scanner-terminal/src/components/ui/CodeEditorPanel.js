import React from 'react';

export default function CodeEditorPanel({ title, value, onChange, readOnly = false, minRows = 10 }) {
  return (
    <label className="code-editor">
      {title && <span>{title}</span>}
      <textarea
        rows={minRows}
        value={value || ''}
        onChange={(event) => onChange?.(event.target.value)}
        readOnly={readOnly}
        spellCheck="false"
      />
    </label>
  );
}
