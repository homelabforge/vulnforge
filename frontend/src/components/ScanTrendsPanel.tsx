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
import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";
import { useScanTrends } from "@/hooks/useVulnForge";
import { ChartSkeleton } from "./LoadingSkeleton";
import type { TrendVelocityMetric } from "@/lib/api";

const numberFormatter = new Intl.NumberFormat();

function formatPercentChange(value: number | null | undefined): string {
  if (value === null || value === undefined) {
    return "—";
  }
  return `${value > 0 ? "+" : ""}${value.toFixed(1)}%`;
}

function formatSeconds(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value < 60) return `${value.toFixed(0)}s`;
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  return seconds === 0 ? `${minutes}m` : `${minutes}m ${seconds}s`;
}

function TrendDelta({
  label,
  metric,
  formatter = (val: number | null | undefined) =>
    val === null || val === undefined ? "—" : numberFormatter.format(val),
  deltaFormatter,
}: {
  label: string;
  metric: TrendVelocityMetric;
  formatter?: (val: number | null | undefined) => string;
  deltaFormatter?: (val: number) => string;
}) {
  const delta = metric.delta ?? 0;
  const direction = delta > 0 ? "up" : delta < 0 ? "down" : "flat";

  const Icon = direction === "up" ? ArrowUpRight : direction === "down" ? ArrowDownRight : Minus;
  const color =
    direction === "up" ? "text-emerald-400" : direction === "down" ? "text-rose-400" : "text-gray-400";

  const renderDelta = () => {
    if (metric.delta === null || metric.delta === undefined) {
      return "0";
    }
    const sign = metric.delta > 0 ? "+" : metric.delta < 0 ? "-" : "";
    if (deltaFormatter) {
      return `${sign}${deltaFormatter(Math.abs(metric.delta))}`;
    }
    return `${sign}${numberFormatter.format(Math.abs(metric.delta))}`;
  };

  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-800 last:border-b-0">
      <div>
        <p className="text-sm text-gray-400">{label}</p>
        <p className="text-xl font-semibold text-white">{formatter(metric.current)}</p>
      </div>
      <div className="flex items-center gap-2">
        <Icon className={`w-5 h-5 ${color}`} />
        <div className="text-right">
          <p className={`text-sm font-medium ${color}`}>
            {renderDelta()}
          </p>
          <p className="text-xs text-gray-500">{formatPercentChange(metric.percent_change)}</p>
        </div>
      </div>
    </div>
  );
}

export function ScanTrendsPanel() {
  const { data, isLoading } = useScanTrends();

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
        <ChartSkeleton />
        <ChartSkeleton />
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const chartData = data.series.map((point) => ({
    date: point.date,
    completed: point.completed_scans,
    failed: point.failed_scans,
    fixable: point.fixable_vulns,
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
      <div className="lg:col-span-2 bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Scan & Remediation Trends</h3>
          <span className="text-xs uppercase tracking-wide text-gray-500">
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
                contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
                labelFormatter={(value) =>
                  new Date(value).toLocaleDateString(undefined, {
                    month: "long",
                    day: "numeric",
                  })
                }
              />
              <Legend />
              <Line type="monotone" dataKey="completed" stroke="#38bdf8" strokeWidth={2} />
              <Line type="monotone" dataKey="fixable" stroke="#22c55e" strokeWidth={2} />
              <Line type="monotone" dataKey="failed" stroke="#f97316" strokeWidth={2} strokeDasharray="5 5" />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="text-center py-12 text-gray-500">No scan activity during this period.</div>
        )}
      </div>

      <div className="bg-[#1a1f2e] border border-emerald-500/30 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-2">Remediation Velocity</h3>
        <p className="text-sm text-gray-400 mb-4">
          Comparing the last 7 days of activity with the prior week to highlight momentum.
        </p>
        <TrendDelta label="Completed scans" metric={data.velocity.completed_scans} />
        <TrendDelta label="Fixable vulnerabilities" metric={data.velocity.fixable_vulns} />
        <TrendDelta
          label="Average scan duration"
          metric={data.velocity.avg_duration_seconds}
          formatter={formatSeconds}
          deltaFormatter={formatSeconds}
        />
      </div>
    </div>
  );
}
