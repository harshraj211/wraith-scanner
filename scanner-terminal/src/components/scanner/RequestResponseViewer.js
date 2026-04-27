import React from 'react';
import CodeEditorPanel from '../ui/CodeEditorPanel';
import EmptyState from '../ui/EmptyState';

export default function RequestResponseViewer({ exchange }) {
  if (!exchange?.request) {
    return <EmptyState title="No exchange selected" body="Select a request from the corpus to inspect HTTP evidence." />;
  }
  const request = exchange.request;
  const response = exchange.response || {};
  const requestText = `${request.method || 'GET'} ${request.url || ''}\n${formatObject(request.headers)}\n\n${formatValue(request.body)}`;
  const responseText = `HTTP ${response.status_code || '---'}\n${formatObject(response.headers)}\n\n${formatValue(response.body_excerpt)}`;
  return (
    <div className="rr-viewer">
      <CodeEditorPanel title="Request" value={requestText} readOnly minRows={14} />
      <CodeEditorPanel title="Response" value={responseText} readOnly minRows={14} />
    </div>
  );
}

function formatObject(value) {
  return Object.entries(value || {}).map(([key, val]) => `${key}: ${val}`).join('\n');
}

function formatValue(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}
