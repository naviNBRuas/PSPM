import { useState, useEffect, useCallback } from "react";
import * as api from "../api";

export default function VaultItems() {
  const [items, setItems] = useState<api.VaultItem[]>([]);
  const [folders, setFolders] = useState<api.Folder[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [showFolderModal, setShowFolderModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingItem, setEditingItem] = useState<api.VaultItem | null>(null);
  const [showPasswordModal, setShowPasswordModal] = useState<string | null>(null);
  const [rotationResult, setRotationResult] = useState<Record<string, string>>({});
  const [rotating, setRotating] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [newFolderName, setNewFolderName] = useState("");
  const [exporting, setExporting] = useState(false);

  const notify = useCallback((type: "success" | "error", msg: string) => {
    setNotification({ type, msg });
    setTimeout(() => setNotification(null), 3000);
  }, []);

  const loadData = useCallback(async () => {
    try {
      const [i, f] = await Promise.all([
        api.listVaultItems(),
        api.listFolders("_all").catch(() => [] as api.Folder[]),
      ]);
      setItems(i);
      setFolders(f);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const filtered = items.filter((item) => {
    const q = search.toLowerCase();
    return (
      item.name.toLowerCase().includes(q) ||
      (item.username?.toLowerCase().includes(q) ?? false) ||
      item.uris.some((u) => u.toLowerCase().includes(q))
    );
  });

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function selectAll() {
    if (selected.size === filtered.length) setSelected(new Set());
    else setSelected(new Set(filtered.map((i) => i.id)));
  }

  const folderMap = new Map(folders.map((f) => [f.id, f.name]));
  function getItemFolder(item: api.VaultItem): string {
    return item.folder_id ? folderMap.get(item.folder_id) ?? "(unknown)" : "(no folder)";
  }

  async function handleDeleteSelected() {
    if (selected.size === 0) return;
    if (!confirm(`Delete ${selected.size} items? This cannot be undone.`)) return;
    try {
      await api.deleteItems(Array.from(selected));
      notify("success", `Deleted ${selected.size} items`);
      setSelected(new Set());
      loadData();
    } catch (e: unknown) {
      notify("error", e instanceof Error ? e.message : "Delete failed");
    }
  }

  async function handleMoveToFolder(folderId: string | null) {
    if (selected.size === 0) return;
    try {
      await api.moveItems(Array.from(selected), folderId);
      notify("success", `Moved ${selected.size} items`);
      setSelected(new Set());
      loadData();
    } catch (e: unknown) {
      notify("error", e instanceof Error ? e.message : "Move failed");
    }
  }

  async function handleRotateSelected() {
    if (selected.size === 0) return;
    if (!confirm(`Rotate passwords for ${selected.size} items? New passwords will be generated.`)) return;
    setRotating(true);
    try {
      const result = await api.rotateBulk(Array.from(selected));
      const pwMap: Record<string, string> = {};
      for (const r of result.results) {
        if (r.new_password) pwMap[r.item_id] = r.new_password;
      }
      setRotationResult(pwMap);
      notify("success", `Rotated ${result.succeeded}/${result.total} passwords`);
      setSelected(new Set());
      loadData();
    } catch (e: unknown) {
      notify("error", e instanceof Error ? e.message : "Rotation failed");
    } finally {
      setRotating(false);
    }
  }

  async function handleSaveEdit() {
    if (!editingItem) return;
    try {
      await api.updateItem({ id: editingItem.id, name: editingItem.name, username: editingItem.username ?? undefined, notes: editingItem.notes ?? undefined, uris: editingItem.uris, favorite: editingItem.favorite, mfa_enabled: editingItem.mfa_enabled });
      notify("success", "Item updated");
      setShowEditModal(false);
      setEditingItem(null);
      loadData();
    } catch (e: unknown) {
      notify("error", e instanceof Error ? e.message : "Update failed");
    }
  }

  async function handleCreateFolder() {
    if (!newFolderName.trim()) return;
    try {
      const vaults = await api.listVaults();
      if (vaults.length === 0) { notify("error", "No vaults exist"); return; }
      await api.createFolder(vaults[0].id, newFolderName.trim());
      notify("success", "Folder created");
      setNewFolderName("");
      setShowFolderModal(false);
      loadData();
    } catch (e: unknown) {
      notify("error", e instanceof Error ? e.message : "Create folder failed");
    }
  }

  async function handleExport() {
    setExporting(true);
    try {
      const { format, data } = await api.exportVault();
      const blob = new Blob([data], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pspm-export.${format === "bitwarden_json" ? "json" : format}`;
      a.click();
      URL.revokeObjectURL(url);
      notify("success", "Exported successfully");
    } catch (e: unknown) {
      notify("error", e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  if (loading) return <div className="text-gray-400 p-4">Loading vault items...</div>;
  if (error) return <div className="text-red-400 p-4">{error}</div>;

  const getStrengthColor = (s: string | null) => {
    switch (s) {
      case "APlus": case "A": return "text-emerald-400";
      case "B": return "text-blue-400";
      case "C": return "text-yellow-400";
      case "D": case "F": return "text-red-400";
      default: return "text-gray-500";
    }
  };

  return (
    <div>
      {/* Notification */}
      {notification && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-2 rounded-lg shadow-lg text-sm ${notification.type === "success" ? "bg-emerald-600 text-white" : "bg-red-600 text-white"}`}>
          {notification.msg}
        </div>
      )}

      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Vault Items</h2>
        <div className="flex gap-2">
          <button onClick={handleExport} disabled={exporting} className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">{exporting ? "..." : "Export"}</button>
          <button onClick={() => setShowFolderModal(true)} className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">+ Folder</button>
        </div>
      </div>

      {/* Search + Bulk Actions */}
      <div className="flex gap-3 mb-4 items-center flex-wrap">
        <input
          type="text"
          placeholder="Search items..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm w-64 focus:outline-none focus:border-emerald-500"
        />
        <span className="text-xs text-gray-500">{filtered.length}/{items.length} items</span>

        {selected.size > 0 && (
          <div className="flex gap-2 ml-auto items-center">
            <span className="text-xs text-emerald-400">{selected.size} selected</span>
            <select
              onChange={(e) => { const v = e.target.value; if (v === "rotate") handleRotateSelected(); else if (v === "delete") handleDeleteSelected(); else if (v) handleMoveToFolder(v === "_none" ? null : v); e.target.value = ""; }}
              className="bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-sm"
              defaultValue=""
            >
              <option value="" disabled>Bulk action...</option>
              <option value="rotate">Rotate Passwords</option>
              <option value="delete">Delete</option>
              <optgroup label="Move to folder">
                <option value="_none">(no folder)</option>
                {folders.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
              </optgroup>
            </select>
          </div>
        )}
      </div>

      {/* Table */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700 text-left text-gray-400">
              <th className="p-3 w-8">
                <input type="checkbox" onChange={selectAll} checked={selected.size === filtered.length && filtered.length > 0} className="accent-emerald-500" />
              </th>
              <th className="p-3">Name</th>
              <th className="p-3">Username</th>
              <th className="p-3">Website</th>
              <th className="p-3">Folder</th>
              <th className="p-3">Strength</th>
              <th className="p-3">Breach</th>
              <th className="p-3">Updated</th>
              <th className="p-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((item) => (
              <tr key={item.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                <td className="p-3">
                  <input type="checkbox" checked={selected.has(item.id)} onChange={() => toggleSelect(item.id)} className="accent-emerald-500" />
                </td>
                <td className="p-3 font-medium">{item.name}</td>
                <td className="p-3 text-gray-400">{item.username ?? "—"}</td>
                <td className="p-3 text-gray-400 max-w-[200px] truncate">{item.uris[0] ?? "—"}</td>
                <td className="p-3 text-xs text-gray-500">{getItemFolder(item)}</td>
                <td className={`p-3 font-mono text-xs ${getStrengthColor(item.strength)}`}>{item.strength ?? "?"}</td>
                <td className="p-3">
                  {item.breach_detail?.password_breached ? (
                    <span className="text-red-400 text-xs font-medium">{item.breach_detail.breach_count}x breached</span>
                  ) : item.breach_detail ? (
                    <span className="text-emerald-400 text-xs">Clean</span>
                  ) : (
                    <span className="text-gray-500 text-xs">—</span>
                  )}
                </td>
                <td className="p-3 text-xs text-gray-500">{new Date(item.updated_at).toLocaleDateString()}</td>
                <td className="p-3">
                  <div className="flex gap-1">
                    <button onClick={() => { setEditingItem({ ...item }); setShowEditModal(true); }} className="px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs" title="Edit">✎</button>
                    <button onClick={async () => { try { const r = await api.rotatePassword(item.id); setRotationResult({ [item.id]: r.new_password }); notify("success", "Password rotated"); loadData(); } catch { notify("error", "Rotation failed"); } }} className="px-2 py-1 bg-amber-700 hover:bg-amber-600 rounded text-xs" title="Rotate password">↻</button>
                    <button onClick={() => setShowPasswordModal(item.id)} className="px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs" title="Show password">
                      {showPasswordModal === item.id && rotationResult[item.id] ? rotationResult[item.id].substring(0, 8) + "..." : "👁"}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={9} className="p-6 text-center text-gray-500">No items found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Password display modal */}
      {showPasswordModal && rotationResult[showPasswordModal] && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowPasswordModal(null)}>
          <div className="bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 border border-gray-700" onClick={(e) => e.stopPropagation()}>
            <h3 className="font-bold mb-3">New Password</h3>
            <div className="bg-gray-900 rounded-lg p-3 font-mono text-sm break-all select-all mb-4">{rotationResult[showPasswordModal]}</div>
            <button onClick={() => { navigator.clipboard.writeText(rotationResult[showPasswordModal]); notify("success", "Copied!"); }} className="bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg text-sm w-full">Copy to Clipboard</button>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {showEditModal && editingItem && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowEditModal(false)}>
          <div className="bg-gray-800 rounded-xl p-6 max-w-lg w-full mx-4 border border-gray-700" onClick={(e) => e.stopPropagation()}>
            <h3 className="font-bold mb-4">Edit Item</h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Name</label>
                <input value={editingItem.name} onChange={(e) => setEditingItem({ ...editingItem, name: e.target.value })} className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm w-full focus:outline-none focus:border-emerald-500" />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Username</label>
                <input value={editingItem.username ?? ""} onChange={(e) => setEditingItem({ ...editingItem, username: e.target.value || null })} className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm w-full focus:outline-none focus:border-emerald-500" />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Notes</label>
                <textarea value={editingItem.notes ?? ""} onChange={(e) => setEditingItem({ ...editingItem, notes: e.target.value || null })} className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm w-full h-20 focus:outline-none focus:border-emerald-500" />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Websites (one per line)</label>
                <textarea value={editingItem.uris.join("\n")} onChange={(e) => setEditingItem({ ...editingItem, uris: e.target.value.split("\n").filter(Boolean) })} className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm w-full h-16 focus:outline-none focus:border-emerald-500" />
              </div>
              <div className="flex gap-4">
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={editingItem.favorite ?? false} onChange={(e) => setEditingItem({ ...editingItem, favorite: e.target.checked })} className="accent-emerald-500" />
                  Favorite
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={editingItem.mfa_enabled ?? false} onChange={(e) => setEditingItem({ ...editingItem, mfa_enabled: e.target.checked })} className="accent-emerald-500" />
                  MFA Enabled
                </label>
              </div>
            </div>
            <div className="flex gap-2 mt-6 justify-end">
              <button onClick={() => setShowEditModal(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">Cancel</button>
              <button onClick={handleSaveEdit} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-sm">Save</button>
            </div>
          </div>
        </div>
      )}

      {/* Create Folder Modal */}
      {showFolderModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowFolderModal(false)}>
          <div className="bg-gray-800 rounded-xl p-6 max-w-sm w-full mx-4 border border-gray-700" onClick={(e) => e.stopPropagation()}>
            <h3 className="font-bold mb-4">Create Folder</h3>
            <input
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              placeholder="Folder name..."
              className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm w-full focus:outline-none focus:border-emerald-500"
              onKeyDown={(e) => e.key === "Enter" && handleCreateFolder()}
            />
            <div className="flex gap-2 mt-4 justify-end">
              <button onClick={() => setShowFolderModal(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">Cancel</button>
              <button onClick={handleCreateFolder} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-sm">Create</button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk rotation results banner */}
      {Object.keys(rotationResult).length > 0 && !showPasswordModal && (
        <div className="mt-4 bg-gray-800 rounded-xl border border-gray-700 p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-sm">Rotation Results</h3>
            <button onClick={() => setRotationResult({})} className="text-xs text-gray-500 hover:text-gray-300">Dismiss</button>
          </div>
          <div className="max-h-40 overflow-y-auto space-y-1">
            {Object.entries(rotationResult).map(([id, pw]) => (
              <div key={id} className="flex items-center gap-2 text-xs">
                <span className="text-gray-400 truncate max-w-[200px]">{items.find(i => i.id === id)?.name ?? id}</span>
                <code className="text-emerald-400 font-mono truncate flex-1">{pw}</code>
                <button onClick={() => navigator.clipboard.writeText(pw)} className="text-gray-500 hover:text-gray-300">📋</button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
