import React from 'react';
import DataTable from '../ui/DataTable';
import Badge from '../ui/Badge';

export default function EvidenceTable({ requests = [], selectedExchange, onSelect, onSendToRepeater, onSendToIntruder }) {
  return (
    <DataTable
      columns={[
        { key: 'method', label: 'Method', width: '82px', render: (row) => <Badge tone={methodTone(row.method)}>{row.method}</Badge> },
        { key: 'url', label: 'URL', width: 'minmax(260px, 1fr)' },
        { key: 'source', label: 'Source', width: '100px' },
        { key: 'auth_role', label: 'Role', width: '110px' },
        {
          key: 'actions',
          label: 'Actions',
          width: '180px',
          render: (row) => (
            <span className="row-actions">
              <button onClick={(event) => { event.stopPropagation(); onSendToRepeater?.(row); }}>Repeater</button>
              <button onClick={(event) => { event.stopPropagation(); onSendToIntruder?.(row); }}>Intruder</button>
            </span>
          ),
        },
      ]}
      rows={requests}
      rowKey="request_id"
      onRowClick={(row) => onSelect?.(row.request_id)}
      emptyTitle={selectedExchange ? 'No filtered rows' : 'No corpus traffic loaded'}
    />
  );
}

function methodTone(method) {
  const value = String(method || '').toUpperCase();
  if (value === 'GET') return 'blue';
  if (value === 'POST') return 'cyan';
  if (['PUT', 'PATCH'].includes(value)) return 'amber';
  if (value === 'DELETE') return 'red';
  return 'slate';
}
