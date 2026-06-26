import React, { useEffect, useState } from 'react';
import axios from 'axios';

const PAGE_SIZE = 50;

const PaginatedDataTable = ({
  selectedFindingId = '',
  onSelectFinding,
  onLoadedPage,
  apiKey = '',
  severity = '',
}) => {
  const [findings, setFindings] = useState([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchFindings = async () => {
      setLoading(true);
      try {
        const storedApiKey = typeof window !== 'undefined' ? window.localStorage.getItem('wraith.apiKey') || '' : '';
        const effectiveApiKey = apiKey || storedApiKey;
        const response = await axios.get('/api/v1/findings', {
          params: { page, limit: PAGE_SIZE, severity: severity || undefined },
          headers: effectiveApiKey ? { 'X-API-KEY': effectiveApiKey } : undefined,
        });
        const nextFindings = response.data.data || [];
        setFindings(nextFindings);
        setTotalPages(response.data.pagination?.total_pages || 1);
        onLoadedPage?.(nextFindings, response.data.pagination || {});
      } catch (error) {
        console.error('Failed to fetch findings', error);
      } finally {
        setLoading(false);
      }
    };

    fetchFindings();
  }, [page, severity, apiKey, onLoadedPage]);

  return (
    <div className="bg-gray-800 p-4 rounded-lg shadow-xl text-white">
      <h2 className="text-xl font-bold mb-4">Vulnerability Findings</h2>
      <div className="overflow-x-auto">
        <table className="min-w-full bg-gray-900 rounded">
          <thead>
            <tr className="border-b border-gray-700 text-gray-400 text-sm">
              <th className="p-3 text-left">ID</th>
              <th className="p-3 text-left">Vulnerability</th>
              <th className="p-3 text-left">Severity</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan="3" className="p-4 text-center animate-pulse">Loading...</td></tr>
            ) : (
              findings.map((finding) => (
                <tr
                  key={finding.finding_id || finding.id}
                  onClick={() => onSelectFinding?.(finding)}
                  className={`border-b border-gray-800 hover:bg-gray-700 cursor-pointer ${selectedFindingId === (finding.finding_id || finding.id) ? 'bg-gray-700' : ''}`}
                >
                  <td className="p-3">{finding.finding_id || finding.id}</td>
                  <td className="p-3">{finding.title || finding.type}</td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs ${finding.severity === 'CRITICAL' ? 'bg-red-600' : 'bg-yellow-600'}`}>
                      {finding.severity}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex justify-between items-center mt-4">
        <button
          onClick={() => setPage((p) => Math.max(p - 1, 1))}
          disabled={page === 1 || loading}
          className="px-4 py-2 bg-gray-700 rounded disabled:opacity-50 hover:bg-gray-600"
        >
          Previous
        </button>
        <span className="text-gray-400">Page {page} of {totalPages}</span>
        <button
          onClick={() => setPage((p) => p + 1)}
          disabled={page >= totalPages || loading}
          className="px-4 py-2 bg-gray-700 rounded disabled:opacity-50 hover:bg-gray-600"
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default PaginatedDataTable;
