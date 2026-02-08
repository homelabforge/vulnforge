/**
 * FindingsTable - Grouped compliance findings with expandable details.
 */

import { useState, useMemo } from "react";
import { ChevronDown, ChevronRight, CheckCircle, AlertCircle, XCircle, Info, Copy, Check, Container, Server } from "lucide-react";
import { getStatusBadge, getSeverityBadge, groupFindings } from "./complianceUtils";
import type { ComplianceFinding } from "./types";

interface FindingsTableProps {
  findings: ComplianceFinding[] | undefined;
  isLoading: boolean;
  onIgnore: (finding: ComplianceFinding) => void;
  onUnignore: (findingId: number) => void;
  unignorePending: boolean;
}

export function FindingsTable({ findings, isLoading, onIgnore, onUnignore, unignorePending }: FindingsTableProps): React.ReactElement {
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const groupedFindings = useMemo(() => groupFindings(findings || []), [findings]);

  const toggleGroupExpanded = (checkId: string): void => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(checkId)) {
        next.delete(checkId);
      } else {
        next.add(checkId);
      }
      return next;
    });
  };

  const copyToClipboard = async (text: string, field: string): Promise<void> => {
    await navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <div className="bg-vuln-surface rounded-lg border border-vuln-border overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-vuln-surface-light">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider w-8" />
              <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                Check ID
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                Title
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                Results
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                Severity
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                Category
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {isLoading ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-vuln-text-muted">
                  Loading findings...
                </td>
              </tr>
            ) : groupedFindings.length > 0 ? (
              groupedFindings.map((group) => {
                const isExpanded = expandedGroups.has(group.check_id);
                const hasDetails = group.remediation || group.description || group.hasTargets;
                const totalFindings = group.passCount + group.warnCount + group.failCount + group.infoCount;

                return (
                  <>
                    {/* Group Header Row */}
                    <tr
                      key={group.check_id}
                      className={`hover:bg-vuln-surface-light transition-colors ${hasDetails ? "cursor-pointer" : ""}`}
                      onClick={() => hasDetails && toggleGroupExpanded(group.check_id)}
                    >
                      <td className="px-4 py-3 whitespace-nowrap">
                        {hasDetails && (
                          <button className="text-vuln-text-muted hover:text-vuln-text">
                            {isExpanded ? (
                              <ChevronDown className="w-4 h-4" />
                            ) : (
                              <ChevronRight className="w-4 h-4" />
                            )}
                          </button>
                        )}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="text-sm text-vuln-text font-mono">{group.check_id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-vuln-text">{group.title}</span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          {group.passCount > 0 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/20 text-green-400">
                              <CheckCircle className="w-3 h-3" />
                              {group.passCount}
                            </span>
                          )}
                          {group.warnCount > 0 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400">
                              <AlertCircle className="w-3 h-3" />
                              {group.warnCount}
                            </span>
                          )}
                          {group.failCount > 0 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-400">
                              <XCircle className="w-3 h-3" />
                              {group.failCount}
                            </span>
                          )}
                          {group.infoCount > 0 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400">
                              <Info className="w-3 h-3" />
                              {group.infoCount}
                            </span>
                          )}
                          {!group.hasTargets && totalFindings === 1 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-vuln-text-disabled/20 text-vuln-text-muted">
                              <Server className="w-3 h-3" />
                              System
                            </span>
                          )}
                          {group.hasTargets && (
                            <span className="text-xs text-vuln-text-muted">
                              ({totalFindings} {totalFindings === 1 ? "container" : "containers"})
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        {getSeverityBadge(group.severity)}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-vuln-text-muted">{group.category}</span>
                      </td>
                    </tr>

                    {/* Expanded Details */}
                    {isExpanded && (
                      <tr key={`${group.check_id}-details`} className="bg-vuln-bg">
                        <td colSpan={6} className="px-4 py-4">
                          <div className="space-y-4">
                            {/* Description */}
                            {group.description && (
                              <div>
                                <h4 className="text-sm font-medium text-vuln-text mb-2">Description</h4>
                                <p className="text-sm text-vuln-text-muted">{group.description}</p>
                              </div>
                            )}

                            {/* Remediation */}
                            {group.remediation && (
                              <div>
                                <h4 className="text-sm font-medium text-vuln-text mb-2 flex items-center gap-2">
                                  Remediation
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      copyToClipboard(group.remediation || "", `remediation-${group.check_id}`);
                                    }}
                                    className="text-vuln-text-muted hover:text-blue-400 transition-colors"
                                    title="Copy remediation"
                                  >
                                    {copiedField === `remediation-${group.check_id}` ? (
                                      <Check className="w-4 h-4 text-green-400" />
                                    ) : (
                                      <Copy className="w-4 h-4" />
                                    )}
                                  </button>
                                </h4>
                                <pre className="text-xs bg-vuln-surface p-3 rounded overflow-x-auto text-vuln-text-muted whitespace-pre-wrap">
                                  {group.remediation}
                                </pre>
                              </div>
                            )}

                            {/* Individual Container Results */}
                            {group.hasTargets && (
                              <div>
                                <h4 className="text-sm font-medium text-vuln-text mb-2">Container Results</h4>
                                <div className="bg-vuln-surface rounded-lg border border-vuln-border overflow-hidden">
                                  <table className="w-full">
                                    <thead className="bg-vuln-surface-light">
                                      <tr>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-vuln-text-muted uppercase">Status</th>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-vuln-text-muted uppercase">Container</th>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-vuln-text-muted uppercase">Current Value</th>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-vuln-text-muted uppercase">Actions</th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-700">
                                      {group.findings
                                        .sort((a, b) => {
                                          const order: Record<string, number> = { FAIL: 0, WARN: 1, INFO: 2, NOTE: 3, PASS: 4 };
                                          return (order[a.status] ?? 5) - (order[b.status] ?? 5);
                                        })
                                        .map((finding) => (
                                          <tr
                                            key={finding.id}
                                            className={`hover:bg-vuln-surface-light ${finding.is_ignored ? "opacity-50" : ""}`}
                                          >
                                            <td className="px-3 py-2 whitespace-nowrap">
                                              {getStatusBadge(finding.status)}
                                            </td>
                                            <td className="px-3 py-2 whitespace-nowrap">
                                              {finding.target ? (
                                                <span className="inline-flex items-center gap-1 text-sm text-vuln-text">
                                                  <Container className="w-3 h-3 text-purple-400" />
                                                  {finding.target}
                                                </span>
                                              ) : (
                                                <span className="inline-flex items-center gap-1 text-sm text-vuln-text-muted">
                                                  <Server className="w-3 h-3" />
                                                  System
                                                </span>
                                              )}
                                            </td>
                                            <td className="px-3 py-2">
                                              {finding.actual_value && (
                                                <code className="text-xs bg-vuln-bg px-2 py-1 rounded text-vuln-text-muted">
                                                  {finding.actual_value}
                                                </code>
                                              )}
                                            </td>
                                            <td className="px-3 py-2 whitespace-nowrap">
                                              {finding.is_ignored ? (
                                                <button
                                                  onClick={(e) => {
                                                    e.stopPropagation();
                                                    onUnignore(finding.id);
                                                  }}
                                                  disabled={unignorePending}
                                                  className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50"
                                                >
                                                  Unignore
                                                </button>
                                              ) : finding.status !== "PASS" ? (
                                                <button
                                                  onClick={(e) => {
                                                    e.stopPropagation();
                                                    onIgnore(finding);
                                                  }}
                                                  className="text-xs text-vuln-text-muted hover:text-vuln-text"
                                                >
                                                  Mark as False Positive
                                                </button>
                                              ) : null}
                                            </td>
                                          </tr>
                                        ))}
                                    </tbody>
                                  </table>
                                </div>
                              </div>
                            )}

                            {/* System check (non-container) details */}
                            {!group.hasTargets && group.findings.length === 1 && (
                              <div className="flex items-center justify-between">
                                <div>
                                  {group.findings[0].actual_value && (
                                    <div className="flex items-start gap-2">
                                      <span className="text-xs text-vuln-text-disabled min-w-16">Current:</span>
                                      <code className="text-xs bg-vuln-surface px-2 py-1 rounded text-vuln-text-muted">
                                        {group.findings[0].actual_value}
                                      </code>
                                    </div>
                                  )}
                                  {group.findings[0].expected_value && (
                                    <div className="flex items-start gap-2 mt-1">
                                      <span className="text-xs text-vuln-text-disabled min-w-16">Expected:</span>
                                      <code className="text-xs bg-vuln-surface px-2 py-1 rounded text-green-400">
                                        {group.findings[0].expected_value}
                                      </code>
                                    </div>
                                  )}
                                </div>
                                {group.findings[0].status !== "PASS" && !group.findings[0].is_ignored && (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      onIgnore(group.findings[0]);
                                    }}
                                    className="text-xs text-vuln-text-muted hover:text-vuln-text"
                                  >
                                    Mark as False Positive
                                  </button>
                                )}
                                {group.findings[0].is_ignored && (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      onUnignore(group.findings[0].id);
                                    }}
                                    disabled={unignorePending}
                                    className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50"
                                  >
                                    Unignore
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })
            ) : (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-vuln-text-muted">
                  No findings found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
