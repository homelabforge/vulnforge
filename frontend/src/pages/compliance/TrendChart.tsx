/**
 * TrendChart - 30-day compliance score trend line chart.
 */

import { TrendingUp } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import type { TrendDataPoint } from "./types";

interface TrendChartProps {
  trendData: TrendDataPoint[];
}

export function TrendChart({ trendData }: TrendChartProps): React.ReactElement {
  return (
    <div className="mb-6 p-6 bg-vuln-surface rounded-lg border border-vuln-border">
      <div className="flex items-center gap-2 mb-4">
        <TrendingUp className="w-5 h-5 text-cyan-500" />
        <h2 className="text-xl font-semibold text-vuln-text">Compliance Trend (30 Days)</h2>
      </div>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={trendData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis
            dataKey="date"
            stroke="#9CA3AF"
            tickFormatter={(value) => new Date(value).toLocaleDateString()}
          />
          <YAxis stroke="#9CA3AF" domain={[0, 100]} />
          <Tooltip
            content={({ active, payload, label }) => {
              if (active && payload && payload.length) {
                return (
                  <div className="bg-vuln-surface border border-vuln-border rounded-lg p-3 shadow-lg">
                    <p className="font-semibold text-vuln-text mb-2">
                      {label ? new Date(label).toLocaleString() : "Unknown"}
                    </p>
                    {payload.map((entry, index) => (
                      <p key={index} className="text-sm" style={{ color: entry.color }}>
                        {entry.name}: {entry.value}%
                      </p>
                    ))}
                  </div>
                );
              }
              return null;
            }}
          />
          <Legend />
          <Line
            type="monotone"
            dataKey="compliance_score"
            name="Compliance Score"
            stroke="#06B6D4"
            strokeWidth={2}
            dot={{ fill: "#06B6D4" }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
