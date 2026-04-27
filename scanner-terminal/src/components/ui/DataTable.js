import React from 'react';
import EmptyState from './EmptyState';

export default function DataTable({ columns, rows, rowKey = 'id', onRowClick, emptyTitle }) {
  return (
    <div className="data-table">
      <div className="data-table-head" style={{ gridTemplateColumns: columns.map((col) => col.width || 'minmax(0, 1fr)').join(' ') }}>
        {columns.map((col) => <span key={col.key}>{col.label}</span>)}
      </div>
      <div className="data-table-body">
        {rows?.length ? rows.map((row, index) => (
          <div
            className="data-table-row"
            key={row[rowKey] || index}
            role="button"
            tabIndex={0}
            onClick={() => onRowClick?.(row)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') onRowClick?.(row);
            }}
            style={{ gridTemplateColumns: columns.map((col) => col.width || 'minmax(0, 1fr)').join(' ') }}
          >
            {columns.map((col) => (
              <span key={col.key}>{col.render ? col.render(row) : row[col.key]}</span>
            ))}
          </div>
        )) : <EmptyState title={emptyTitle || 'No rows'} />}
      </div>
    </div>
  );
}
