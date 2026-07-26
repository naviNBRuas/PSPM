import { useState, useEffect } from "react";
import * as api from "../api";

export default function AuditLog() {
  const [entries, setEntries] = useState<api.AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const { entries } = await api.listAuditLogs();
        setEntries(entries);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load audit log");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filtered = filter
    ? entries.filter((e) => e.action.toLowerCase().includes(filter.toLowerCase()) || e.details?.toLowerCase().includes(filter.toLowerCase()))
    : entries;

  if (loading) return <div className="text-gray-400 p-4">Loading audit log...</div>;
  if (error) return <div className="text-red-400 p-4">{error}</div>;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Audit Log</h2>
        <span className="text-xs text-gray-500">{entries.length} entries</span>
      </div>

      <input
        type="text"
        placeholder="Filter by action or details..."
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm w-72 mb-4 focus:outline-none focus:border-emerald-500"
      />

      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700 text-left text-gray-400">
              <th className="p-3">Timestamp</th>
              <th className="p-3">Action</th>
              <th className="p-3">Item ID</th>
              <th className="p-3">Details</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((entry) => (
              <tr key={entry.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                <td className="p-3 text-xs text-gray-400 whitespace-nowrap">
                  {new Date(entry.created_at).toLocaleString()}
                </td>
                <td className="p-3">
                  <span className="text-emerald-400 font-medium">{entry.action}</span>
                </td>
                <td className="p-3 text-xs text-gray-500 font-mono">
                  {entry.item_id ? entry.item_id.substring(0, 8) + "..." : "—"}
                </td>
                <td className="p-3 text-gray-400 max-w-md truncate">{entry.details ?? "—"}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={4} className="p-6 text-center text-gray-500">No audit entries found</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
