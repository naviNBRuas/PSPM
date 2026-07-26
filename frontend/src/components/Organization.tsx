import { useState, useEffect, useCallback } from "react";
import * as api from "../api";

export default function Organization() {
  const [groups, setGroups] = useState<api.DuplicateGroupResponse[]>([]);
  const [items, setItems] = useState<api.VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [merging, setMerging] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [autoSort, setAutoSort] = useState(false);

  const notify = useCallback((type: "success" | "error", msg: string) => {
    setNotification({ type, msg });
    setTimeout(() => setNotification(null), 3000);
  }, []);

  const loadData = useCallback(async () => {
    try {
      const i = await api.listVaultItems();
      setItems(i);
    } catch {
      // silently fail
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  async function handleScan() {
    setScanning(true);
    try {
      const result = await api.findDuplicates();
      setGroups(result.groups);
      notify("success", `Found ${result.groups.length} duplicate groups`);
    } catch (e: unknown) {
      notify("error", e instanceof Error ? e.message : "Scan failed");
    } finally {
      setScanning(false);
      setLoading(false);
    }
  }

  async function handleMerge(group: api.DuplicateGroupResponse) {
    if (!confirm(`Merge ${group.duplicate_item_ids.length} duplicates into "${getItemName(group.canonical_item_id)}"?`)) return;
    setMerging(true);
    try {
      await api.mergeDuplicates(group.canonical_item_id, group.duplicate_item_ids, true);
      notify("success", "Duplicates merged");
      setGroups((prev) => prev.filter((g) => g.canonical_item_id !== group.canonical_item_id));
      loadData();
    } catch (e: unknown) {
      notify("error", e instanceof Error ? e.message : "Merge failed");
    } finally {
      setMerging(false);
    }
  }

  async function handleMergeAll() {
    if (!confirm(`Merge all ${groups.length} duplicate groups?`)) return;
    setMerging(true);
    let merged = 0;
    for (const group of groups) {
      try {
        await api.mergeDuplicates(group.canonical_item_id, group.duplicate_item_ids, true);
        merged++;
      } catch {
        // skip failures
      }
    }
    notify("success", `Merged ${merged}/${groups.length} groups`);
    setGroups([]);
    loadData();
    setMerging(false);
  }

  function getItemName(id: string): string {
    return items.find((i) => i.id === id)?.name ?? id.substring(0, 8);
  }

  const matchReasonLabel: Record<string, string> = {
    SamePasswordHash: "Same password hash",
    SameWebsite: "Same website",
    SameUsername: "Same username",
    SameTitle: "Same title",
    SameWebsiteAndUsername: "Same website + username",
    SameUri: "Same URI",
  };

  return (
    <div>
      {notification && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-2 rounded-lg shadow-lg text-sm ${notification.type === "success" ? "bg-emerald-600 text-white" : "bg-red-600 text-white"}`}>
          {notification.msg}
        </div>
      )}

      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Organization</h2>
        <div className="flex gap-2">
          {groups.length > 0 && (
            <button onClick={handleMergeAll} disabled={merging} className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded-lg text-sm">
              {merging ? "Merging..." : `Merge All (${groups.length})`}
            </button>
          )}
          <button onClick={handleScan} disabled={scanning} className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg text-sm">
            {scanning ? "Scanning..." : "Scan for Duplicates"}
          </button>
        </div>
      </div>

      {/* Duplicate Groups */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 mb-6">
        <h3 className="font-semibold mb-3">Duplicate Groups</h3>
        {groups.length === 0 && !loading ? (
          <div className="text-gray-500 text-sm py-4 text-center">
            {scanning ? "Scanning..." : "No duplicate groups found. Click 'Scan for Duplicates' to check."}
          </div>
        ) : (
          <div className="space-y-3">
            {groups.map((group, idx) => (
              <div key={idx} className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{getItemName(group.canonical_item_id)}</span>
                    <span className="text-xs bg-gray-700 px-2 py-0.5 rounded">{matchReasonLabel[group.match_reason] ?? group.match_reason}</span>
                    {group.can_merge && <span className="text-xs text-emerald-400">Mergeable</span>}
                  </div>
                  <button onClick={() => handleMerge(group)} disabled={!group.can_merge || merging} className="px-2 py-1 bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed rounded text-xs">
                    Merge {group.duplicate_item_ids.length} duplicates →
                  </button>
                </div>
                <div className="text-xs text-gray-500 space-y-0.5">
                  <div>Keep: <strong>{getItemName(group.canonical_item_id)}</strong></div>
                  <div>Remove: {group.duplicate_item_ids.map((id) => getItemName(id)).join(", ")}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Folder Overview */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-4">
        <h3 className="font-semibold mb-3">Vault Organization Tips</h3>
        <ul className="space-y-2 text-sm text-gray-400">
          <li className="flex items-start gap-2">
            <span className="text-emerald-400 mt-0.5">📁</span>
            <span>Use <strong>folders</strong> to categorize items (Social, Finance, Work, etc.)</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-emerald-400 mt-0.5">🔄</span>
            <span>Run <strong>bulk rotation</strong> on reused/weak passwords from the Vault page</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-emerald-400 mt-0.5">🔍</span>
            <span>Scan for <strong>duplicates</strong> regularly and merge to keep your vault clean</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-emerald-400 mt-0.5">🏷️</span>
            <span>Use <strong>favorites</strong> and enable <strong>MFA</strong> flags on items that support it</span>
          </li>
        </ul>
      </div>
    </div>
  );
}
