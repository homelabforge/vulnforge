/**
 * CategoryBreakdown - Clickable category score cards with progress bars.
 */

import { getScoreColor } from "./complianceUtils";

interface CategoryBreakdownProps {
  categoryBreakdown: { [key: string]: number };
  categoryFilter: string;
  onCategoryFilter: (category: string) => void;
}

export function CategoryBreakdown({ categoryBreakdown, categoryFilter, onCategoryFilter }: CategoryBreakdownProps): React.ReactElement {
  return (
    <div className="mb-6">
      <h2 className="text-xl font-semibold text-vuln-text mb-4">Category Breakdown</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {Object.entries(categoryBreakdown).map(([category, score]) => (
          <div
            key={category}
            className="p-4 bg-vuln-surface rounded-lg border border-vuln-border hover:border-vuln-border-light transition-colors cursor-pointer"
            onClick={() => onCategoryFilter(categoryFilter === category ? "" : category)}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-vuln-text font-medium">{category}</span>
              <span className={`text-lg font-bold ${getScoreColor(score)}`}>
                {score.toFixed(0)}%
              </span>
            </div>
            <div className="w-full bg-vuln-surface-light rounded-full h-2">
              <div
                className={`h-2 rounded-full ${
                  score >= 90 ? "bg-green-500" : score >= 70 ? "bg-yellow-500" : "bg-red-500"
                }`}
                style={{ width: `${score}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
