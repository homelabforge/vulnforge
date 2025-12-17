import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { useScanTrends } from "@/hooks/useVulnForge";
import { ChartSkeleton } from "./LoadingSkeleton";

export function ScanTrendsPanel() {
  const { data, isLoading } = useScanTrends();

  if (isLoading) {
    return (
      <div className="mt-6">
        <ChartSkeleton />
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const chartData = data.series.map((point) => ({
    date: point.date,
    total: point.total_vulns,
    critical: point.critical_vulns,
    high: point.high_vulns,
    fixable: point.fixable_vulns,
  }));

  return (
    <div className="mt-6">
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-vuln-text">Vulnerability Trends</h3>
          <span className="text-xs uppercase tracking-wide text-vuln-text-disabled">
            Last {data.window_days} days
          </span>
        </div>
        {chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height={320}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
              <XAxis
                dataKey="date"
                tickFormatter={(value) =>
                  new Date(value).toLocaleDateString(undefined, {
                    month: "short",
                    day: "numeric",
                  })
                }
                stroke="#94a3b8"
              />
              <YAxis stroke="#94a3b8" allowDecimals={false} />
              <Tooltip
                content={({ active, payload, label }) => {
                  if (active && payload && payload.length) {
                    return (
                      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-3 shadow-lg">
                        <p className="font-semibold text-vuln-text mb-2">
                          {new Date(label).toLocaleDateString(undefined, {
                            month: "long",
                            day: "numeric",
                          })}
                        </p>
                        {payload.map((entry, index) => (
                          <p key={index} className="text-sm" style={{ color: entry.color }}>
                            {entry.name} : {entry.value}
                          </p>
                        ))}
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Legend />
              <Line type="monotone" dataKey="total" name="Total" stroke="#94a3b8" strokeWidth={2} />
              <Line type="monotone" dataKey="critical" name="Critical" stroke="#dc2626" strokeWidth={2} />
              <Line type="monotone" dataKey="high" name="High" stroke="#f97316" strokeWidth={2} />
              <Line type="monotone" dataKey="fixable" name="Fixable" stroke="#22c55e" strokeWidth={2} strokeDasharray="5 5" />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="text-center py-12 text-vuln-text-disabled">No scan activity during this period.</div>
        )}
      </div>
    </div>
  );
}
