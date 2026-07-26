import { useEffect, useState } from "react";
import { getAnalysis, AnalysisReport as AnalysisReportType } from "../api";

const defaultReport: AnalysisReportType = {
  total_logins: 0,
  passwords_reused: 0,
  weak_passwords: 0,
  old_passwords: 0,
  duplicate_entries: 0,
  accounts_without_mfa: 0,
  overall_score: 100,
};

function StatCard({
  label,
  value,
  good,
  suffix = "",
}: {
  label: string;
  value: number;
  good?: boolean;
  suffix?: string;
}) {
  const color =
    good === undefined
      ? "text-gray-100"
      : good
        ? "text-emerald-400"
        : value > 0
          ? "text-red-400"
          : "text-emerald-400";
  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
      <div className="text-sm text-gray-500 mb-1">{label}</div>
      <div className={`text-2xl font-semibold ${color}`}>
        {value}
        {suffix}
      </div>
    </div>
  );
}

export default function AnalysisReport() {
  const [report, setReport] = useState<AnalysisReportType>(defaultReport);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAnalysis()
      .then(setReport)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="text-gray-400">Loading analysis...</div>;
  }

  const hasData = report.total_logins > 0;

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Vault Analysis</h2>

      <div className="flex items-center gap-4 mb-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <div className="text-sm text-gray-400 mb-1">Overall Score</div>
          <div
            className={`text-4xl font-bold ${
              report.overall_score >= 80
                ? "text-emerald-400"
                : report.overall_score >= 60
                  ? "text-yellow-400"
                  : "text-red-400"
            }`}
          >
            {report.overall_score}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <StatCard
          label="Total Logins"
          value={report.total_logins}
          suffix=""
        />
        <StatCard
          label="Passwords Reused"
          value={report.passwords_reused}
          good={report.passwords_reused === 0}
        />
        <StatCard
          label="Weak Passwords"
          value={report.weak_passwords}
          good={report.weak_passwords === 0}
        />
        <StatCard
          label="Old Passwords (>1yr)"
          value={report.old_passwords}
          good={report.old_passwords === 0}
        />
        <StatCard
          label="Without MFA"
          value={report.accounts_without_mfa}
          good={report.accounts_without_mfa === 0}
        />
        <StatCard
          label="Duplicate Entries"
          value={report.duplicate_entries}
          good={report.duplicate_entries === 0}
        />
      </div>

      {!hasData && (
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <p className="text-gray-500 text-sm">
            No vault data found. Import a vault to generate a full analysis report.
          </p>
        </div>
      )}

      {hasData && report.passwords_reused > 0 && (
        <div className="mt-4 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-xl">
          <h3 className="font-semibold text-yellow-400 mb-2">Recommendations</h3>
          <ul className="text-sm text-gray-300 space-y-1">
            {report.passwords_reused > 0 && (
              <li>• {report.passwords_reused} password{report.passwords_reused > 1 ? "s are" : " is"} reused across multiple accounts. Consider using unique passwords.</li>
            )}
            {report.weak_passwords > 0 && (
              <li>• {report.weak_passwords} weak password{report.weak_passwords > 1 ? "s" : ""} detected. Generate stronger passwords.</li>
            )}
            {report.old_passwords > 0 && (
              <li>• {report.old_passwords} password{report.old_passwords > 1 ? "s haven't" : " hasn't"} been changed in over a year.</li>
            )}
            {report.accounts_without_mfa > 0 && (
              <li>• {report.accounts_without_mfa} account{report.accounts_without_mfa > 1 ? "s" : ""} without MFA. Enable two-factor authentication.</li>
            )}
            {report.duplicate_entries > 0 && (
              <li>• {report.duplicate_entries} duplicate entr{report.duplicate_entries > 1 ? "ies" : "y"} found. Consider cleaning up.</li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}
