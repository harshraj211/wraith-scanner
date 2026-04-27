import React from 'react';

export default function CodeEditorPanel({ title, value, onChange, readOnly = false, minRows = 10, placeholder = '' }) {
  return (
    <label className="code-editor">
      {title && <span>{title}</span>}
      <textarea
        rows={minRows}
        value={value || ''}
        onChange={(event) => onChange?.(event.target.value)}
        readOnly={readOnly}
        placeholder={placeholder}
        spellCheck="false"
      />
    </label>
  );
}
