export default function AnalysisReport() {
  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Vault Analysis</h2>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
          <div className="text-sm text-gray-500">Passwords Reused</div>
          <div className="text-2xl font-semibold text-yellow-400">--</div>
        </div>
        <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
          <div className="text-sm text-gray-500">Weak Passwords</div>
          <div className="text-2xl font-semibold text-red-400">--</div>
        </div>
        <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
          <div className="text-sm text-gray-500">Old Passwords (&gt;1yr)</div>
          <div className="text-2xl font-semibold text-orange-400">--</div>
        </div>
        <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
          <div className="text-sm text-gray-500">Without MFA</div>
          <div className="text-2xl font-semibold text-red-400">--</div>
        </div>
        <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
          <div className="text-sm text-gray-500">Duplicates</div>
          <div className="text-2xl font-semibold text-gray-400">--</div>
        </div>
        <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
          <div className="text-sm text-gray-500">Compromised</div>
          <div className="text-2xl font-semibold text-red-400">--</div>
        </div>
      </div>

      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <p className="text-gray-500 text-sm">
          Import a vault first to generate a full analysis report.
        </p>
      </div>
    </div>
  );
}
