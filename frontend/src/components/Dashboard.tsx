import { useState, useEffect, useCallback } from "react";
import * as api from "../api";

export default function Dashboard() {
  const [metrics, setMetrics] = useState<api.DashboardMetrics | null>(null);
  const [breachChecks, setBreachChecks] = useState<{ checks: api.BreachCheckResult[] } | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [m, b] = await Promise.all([
        api.getDashboardMetrics(),
        api.listAuditLogs().catch(() => null),
      ]);
      setMetrics(m);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  if (loading) return <div className="text-gray-400 p-4">Loading dashboard...</div>;
  if (!metrics) return <div className="text-red-400 p-4">Failed to load dashboard</div>;

  const scores = [
    { label: "Overall Score", value: metrics.overall_security_score, max: 100, color: metrics.overall_security_score >= 80 ? "bg-emerald-500" : metrics.overall_security_score >= 50 ? "bg-yellow-500" : "bg-red-500" },
  ];

  const cards = [
    { label: "Total Items", value: metrics.total_items, color: "text-blue-400" },
    { label: "Password Reuse", value: `${metrics.password_reuse_percentage.toFixed(1)}%`, color: metrics.password_reuse_percentage > 30 ? "text-red-400" : "text-emerald-400" },
    { label: "Weak Passwords", value: `${metrics.weak_password_percentage.toFixed(1)}%`, color: metrics.weak_password_percentage > 20 ? "text-red-400" : "text-emerald-400" },
    { label: "Breached", value: `${metrics.breached_password_percentage.toFixed(1)}%`, color: metrics.breached_password_percentage > 0 ? "text-red-400" : "text-emerald-400" },
    { label: "MFA Coverage", value: `${metrics.mfa_coverage_percentage.toFixed(1)}%`, color: metrics.mfa_coverage_percentage > 50 ? "text-emerald-400" : "text-yellow-400" },
    { label: "Duplicates", value: `${metrics.duplicate_percentage.toFixed(1)}%`, color: metrics.duplicate_percentage > 10 ? "text-red-400" : "text-emerald-400" },
    { label: "Avg Password Age", value: `${metrics.password_age_avg_days.toFixed(0)} days`, color: metrics.password_age_avg_days > 365 ? "text-red-400" : "text-gray-400" },
    { label: "Passkeys", value: `${metrics.passkey_adoption_percentage.toFixed(1)}%`, color: metrics.passkey_adoption_percentage > 20 ? "text-emerald-400" : "text-gray-400" },
  ];

  const gradeColors: Record<string, string> = {
    a_plus: "bg-emerald-500", a: "bg-emerald-400", b: "bg-blue-400",
    c: "bg-yellow-400", d: "bg-orange-500", f: "bg-red-500",
  };

  const totalGraded = metrics.grade_distribution.a_plus + metrics.grade_distribution.a + metrics.grade_distribution.b + metrics.grade_distribution.c + metrics.grade_distribution.d + metrics.grade_distribution.f;

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Dashboard</h2>

      {/* Overall Score */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-lg font-semibold">Overall Security Score</span>
          <span className={`text-4xl font-bold ${metrics.overall_security_score >= 80 ? "text-emerald-400" : metrics.overall_security_score >= 50 ? "text-yellow-400" : "text-red-400"}`}>
            {metrics.overall_security_score}/100
          </span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-3">
          <div className={`h-3 rounded-full transition-all ${scores[0].color}`} style={{ width: `${scores[0].value}%` }} />
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {cards.map((card) => (
          <div key={card.label} className="bg-gray-800 rounded-xl p-4 border border-gray-700">
            <div className="text-xs text-gray-500 mb-1">{card.label}</div>
            <div className={`text-xl font-bold ${card.color}`}>{card.value}</div>
          </div>
        ))}
      </div>

      {/* Grade Distribution */}
      {totalGraded > 0 && (
        <div className="bg-gray-800 rounded-xl p-4 border border-gray-700 mb-6">
          <h3 className="text-sm font-semibold mb-3">Password Grade Distribution</h3>
          <div className="flex h-6 rounded-full overflow-hidden">
            {(["a_plus", "a", "b", "c", "d", "f"] as const).map((g) => {
              const count = metrics.grade_distribution[g];
              if (count === 0) return null;
              return (
                <div
                  key={g}
                  className={`${gradeColors[g]} flex items-center justify-center text-xs font-bold text-white transition-all`}
                  style={{ width: `${(count / totalGraded) * 100}%` }}
                  title={`${g.replace("_", "+").toUpperCase()}: ${count}`}
                >
                  {count}
                </div>
              );
            })}
          </div>
          <div className="flex justify-between mt-1 text-xs text-gray-500">
            <span>A+</span><span>A</span><span>B</span><span>C</span><span>D</span><span>F</span>
          </div>
        </div>
      )}

      {/* Recommendations */}

      <div className="bg-gray-800 rounded-xl p-4 border border-gray-700">
        <h3 className="text-sm font-semibold mb-3">Recommendations</h3>
        <ul className="space-y-2 text-sm">
          {metrics.password_reuse_percentage > 20 && (
            <li className="flex items-start gap-2">
              <span className="text-red-400 mt-0.5">⚠</span>
              <span>High password reuse ({metrics.password_reuse_percentage.toFixed(0)}%). Use <strong>Rotate Passwords</strong> to generate unique passwords.</span>
            </li>
          )}
          {metrics.weak_password_percentage > 10 && (
            <li className="flex items-start gap-2">
              <span className="text-yellow-400 mt-0.5">⚠</span>
              <span>{metrics.weak_password_percentage.toFixed(0)}% of passwords are weak. Rotate them with strong generated passwords.</span>
            </li>
          )}
          {metrics.breached_password_percentage > 0 && (
            <li className="flex items-start gap-2">
              <span className="text-red-400 mt-0.5">🚨</span>
              <span>Breached passwords detected! Rotate immediately.</span>
            </li>
          )}
          {metrics.duplicate_percentage > 10 && (
            <li className="flex items-start gap-2">
              <span className="text-yellow-400 mt-0.5">⚠</span>
              <span>{metrics.duplicate_percentage.toFixed(0)}% of entries are duplicates. <strong>Scan for Duplicates</strong> to clean up.</span>
            </li>
          )}
          {metrics.mfa_coverage_percentage < 50 && metrics.total_items > 0 && (
            <li className="flex items-start gap-2">
              <span className="text-yellow-400 mt-0.5">💡</span>
              <span>Enable MFA on accounts that support it (currently {metrics.mfa_coverage_percentage.toFixed(0)}% covered).</span>
            </li>
          )}
          {metrics.password_age_avg_days > 365 && (
            <li className="flex items-start gap-2">
              <span className="text-yellow-400 mt-0.5">⏰</span>
              <span>Average password age is {metrics.password_age_avg_days.toFixed(0)} days. Consider a bulk rotation.</span>
            </li>
          )}
          {metrics.passkey_adoption_percentage < 10 && metrics.total_items > 0 && (
            <li className="flex items-start gap-2">
              <span className="text-gray-400 mt-0.5">💡</span>
              <span>Passkey adoption is low. Consider upgrading supported accounts.</span>
            </li>
          )}
          {metrics.total_items === 0 && (
            <li className="text-gray-500">Import a vault to get started.</li>
          )}
        </ul>
      </div>
    </div>
  );
}
