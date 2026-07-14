import { useEffect, useState } from "react";
import { getDashboardMetrics, DashboardMetrics } from "../api";

const defaultMetrics: DashboardMetrics = {
  overall_security_score: 0,
  total_items: 0,
  password_reuse_percentage: 0,
  weak_password_percentage: 0,
  breached_password_percentage: 0,
  mfa_coverage_percentage: 0,
  passkey_adoption_percentage: 0,
  duplicate_percentage: 0,
  last_audit_date: null,
  password_age_avg_days: 0,
  grade_distribution: { a_plus: 0, a: 0, b: 0, c: 0, d: 0, f: 0 },
};

function ScoreRing({ score }: { score: number }) {
  const color =
    score >= 80
      ? "text-emerald-400"
      : score >= 60
        ? "text-yellow-400"
        : "text-red-400";
  return (
    <div className="flex items-center gap-4">
      <div className={`text-5xl font-bold ${color}`}>{score}</div>
      <div className="text-sm text-gray-400">
        <div>Security</div>
        <div>Score</div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  suffix = "%",
  good,
}: {
  label: string;
  value: number;
  suffix?: string;
  good?: boolean;
}) {
  const color =
    good === undefined
      ? "text-gray-100"
      : good
        ? "text-emerald-400"
        : "text-red-400";
  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
      <div className="text-sm text-gray-500 mb-1">{label}</div>
      <div className={`text-2xl font-semibold ${color}`}>
        {value.toFixed(1)}
        {suffix}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState<DashboardMetrics>(defaultMetrics);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getDashboardMetrics()
      .then(setMetrics)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="text-gray-400">Loading dashboard...</div>;
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Security Dashboard</h2>
        <button className="px-4 py-2 bg-emerald-500 text-black rounded-lg font-medium text-sm hover:bg-emerald-400 transition-colors">
          Run Audit
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800 col-span-1 lg:col-span-1">
          <ScoreRing score={metrics.overall_security_score} />
        </div>
        <StatCard
          label="Total Logins"
          value={metrics.total_items}
          suffix=""
        />
        <StatCard
          label="Password Reuse"
          value={metrics.password_reuse_percentage}
          good={metrics.password_reuse_percentage < 10}
        />
        <StatCard
          label="Weak Passwords"
          value={metrics.weak_password_percentage}
          good={metrics.weak_password_percentage < 5}
        />
        <StatCard
          label="Breached"
          value={metrics.breached_password_percentage}
          good={metrics.breached_password_percentage === 0}
        />
        <StatCard
          label="MFA Coverage"
          value={metrics.mfa_coverage_percentage}
          good={metrics.mfa_coverage_percentage > 80}
        />
        <StatCard
          label="Duplicates"
          value={metrics.duplicate_percentage}
          good={metrics.duplicate_percentage < 2}
        />
        <StatCard
          label="Avg Password Age"
          value={metrics.password_age_avg_days}
          suffix="d"
          good={metrics.password_age_avg_days < 180}
        />
      </div>

      <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
        <h3 className="text-lg font-semibold mb-4">Grade Distribution</h3>
        <div className="flex items-end gap-2 h-32">
          {(
            [
              ["A+", metrics.grade_distribution.a_plus, "emerald"],
              ["A", metrics.grade_distribution.a, "green"],
              ["B", metrics.grade_distribution.b, "lime"],
              ["C", metrics.grade_distribution.c, "yellow"],
              ["D", metrics.grade_distribution.d, "orange"],
              ["F", metrics.grade_distribution.f, "red"],
            ] as const
          ).map(([label, count, color]) => {
            const max = Math.max(
              ...Object.values(metrics.grade_distribution),
              1,
            );
            const height = (count / max) * 100;
            return (
              <div key={label} className="flex-1 flex flex-col items-center">
                <div className="text-xs text-gray-500 mb-1">{count}</div>
                <div
                  className={`w-full rounded-t bg-${color}-500/50`}
                  style={{ height: `${height}%`, minHeight: count > 0 ? 4 : 0 }}
                />
                <div className="text-xs text-gray-400 mt-1">{label}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
