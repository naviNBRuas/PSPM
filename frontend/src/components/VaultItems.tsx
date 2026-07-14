export default function VaultItems() {
  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Vault Items</h2>
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-left">
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Username</th>
                <th className="px-4 py-3 font-medium">Website</th>
                <th className="px-4 py-3 font-medium">Strength</th>
                <th className="px-4 py-3 font-medium">Breached</th>
                <th className="px-4 py-3 font-medium">MFA</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-gray-800/50 text-gray-400">
                <td colSpan={6} className="px-4 py-8 text-center">
                  Import a vault to see items here.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
