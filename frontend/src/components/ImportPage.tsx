import { useState, useRef } from "react";
import { importVault } from "../api";

export default function ImportPage() {
  const [format, setFormat] = useState("bitwarden_json");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    setStatus("Reading file...");
    setError(null);
    try {
      const text = await file.text();
      setStatus("Importing to vault...");
      const result = await importVault(format, text);
      setStatus(
        `Imported ${result.item_count} items successfully. Vault ID: ${result.vault_id}`,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
      setStatus(null);
    }
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Import Vault</h2>

      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800 max-w-xl">
        <label className="block text-sm text-gray-400 mb-2">Source Format</label>
        <select
          className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm mb-6"
          value={format}
          onChange={(e) => setFormat(e.target.value)}
        >
          <option value="bitwarden_json">Bitwarden JSON</option>
          <option value="bitwarden_csv">Bitwarden CSV</option>
        </select>

        <div
          className="border-2 border-dashed border-gray-700 rounded-xl p-12 text-center cursor-pointer hover:border-emerald-500/50 transition-colors"
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            const file = e.dataTransfer.files[0];
            if (file) handleFile(file);
          }}
        >
          <div className="text-4xl mb-3">📥</div>
          <p className="text-gray-400 text-sm">
            Drop your Bitwarden export file here
          </p>
          <p className="text-gray-600 text-xs mt-1">or click to browse</p>
          <input
            ref={fileRef}
            type="file"
            accept=".json,.csv"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFile(file);
            }}
          />
        </div>

        {status && (
          <div className="mt-4 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-sm text-emerald-400">
            {status}
          </div>
        )}

        {error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400">
            {error}
          </div>
        )}
      </div>

      <div className="mt-6 bg-gray-900 rounded-xl p-6 border border-gray-800 max-w-xl">
        <h3 className="font-semibold mb-2">⚠️ Privacy Notice</h3>
        <p className="text-sm text-gray-400">
          Your vault data never leaves your machine. All processing is done
          locally. Passwords are hashed immediately — plaintext is only kept in
          volatile memory during import and discarded after processing.
        </p>
      </div>
    </div>
  );
}
