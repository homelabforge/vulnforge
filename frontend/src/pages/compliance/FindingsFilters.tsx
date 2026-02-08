/**
 * FindingsFilters - Status, category, and ignored filter controls.
 */

import { Filter } from "lucide-react";

interface FindingsFiltersProps {
  statusFilter: string;
  categoryFilter: string;
  showIgnored: boolean;
  categories: string[] | null;
  onStatusFilter: (value: string) => void;
  onCategoryFilter: (value: string) => void;
  onShowIgnored: (value: boolean) => void;
  onClearFilters: () => void;
}

export function FindingsFilters({
  statusFilter,
  categoryFilter,
  showIgnored,
  categories,
  onStatusFilter,
  onCategoryFilter,
  onShowIgnored,
  onClearFilters,
}: FindingsFiltersProps): React.ReactElement {
  const hasActiveFilters = statusFilter || categoryFilter || showIgnored;

  return (
    <div className="mb-4 flex flex-wrap items-center gap-4">
      <div className="flex items-center gap-2">
        <Filter className="w-4 h-4 text-vuln-text-muted" />
        <span className="text-sm text-vuln-text-muted">Filters:</span>
      </div>

      <select
        value={statusFilter}
        onChange={(e) => onStatusFilter(e.target.value)}
        className="px-3 py-1.5 bg-vuln-surface border border-vuln-border rounded-lg text-sm text-vuln-text"
      >
        <option value="">All Statuses</option>
        <option value="PASS">Pass</option>
        <option value="WARN">Warn</option>
        <option value="FAIL">Fail</option>
        <option value="INFO">Info</option>
        <option value="NOTE">Note</option>
      </select>

      {categories && (
        <select
          value={categoryFilter}
          onChange={(e) => onCategoryFilter(e.target.value)}
          className="px-3 py-1.5 bg-vuln-surface border border-vuln-border rounded-lg text-sm text-vuln-text"
        >
          <option value="">All Categories</option>
          {categories.map((cat) => (
            <option key={cat} value={cat}>
              {cat}
            </option>
          ))}
        </select>
      )}

      <label className="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={showIgnored}
          onChange={(e) => onShowIgnored(e.target.checked)}
          className="w-4 h-4 rounded border-vuln-border bg-vuln-surface text-blue-600 focus:ring-blue-500"
        />
        <span className="text-sm text-vuln-text">Show Ignored</span>
      </label>

      {hasActiveFilters && (
        <button
          onClick={onClearFilters}
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          Clear Filters
        </button>
      )}
    </div>
  );
}
