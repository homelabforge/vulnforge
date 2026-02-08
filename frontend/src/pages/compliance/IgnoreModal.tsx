/**
 * IgnoreModal - Mark a compliance finding as false positive.
 */

import { useState } from "react";
import { validateIgnoreReason } from "@/schemas/modals";
import { toast } from "sonner";
import type { ComplianceFinding } from "./types";

interface IgnoreModalProps {
  finding: ComplianceFinding;
  onClose: () => void;
  onSubmit: (findingId: number, reason: string) => void;
  isPending: boolean;
}

export function IgnoreModal({ finding, onClose, onSubmit, isPending }: IgnoreModalProps): React.ReactElement {
  const [ignoreReason, setIgnoreReason] = useState("");

  const handleSubmit = (): void => {
    const validation = validateIgnoreReason(ignoreReason);
    if (!validation.success) {
      toast.error(validation.error);
      return;
    }
    onSubmit(finding.id, validation.data);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-vuln-surface rounded-lg p-6 max-w-lg w-full mx-4 border border-vuln-border">
        <h3 className="text-xl font-semibold text-vuln-text mb-4">Mark as False Positive</h3>
        <p className="text-vuln-text mb-4">
          Check: <span className="font-mono text-blue-400">{finding.check_id}</span> -{" "}
          {finding.title}
        </p>
        <div className="mb-4">
          <label className="block text-sm text-vuln-text-muted mb-2">
            Reason (required)
          </label>
          <textarea
            value={ignoreReason}
            onChange={(e) => setIgnoreReason(e.target.value)}
            placeholder="Explain why this finding is not applicable..."
            className="w-full px-3 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:border-blue-500"
            rows={4}
          />
        </div>
        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-vuln-text-muted hover:text-vuln-text transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={!ignoreReason.trim() || isPending}
            className="px-3 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-vuln-surface disabled:cursor-not-allowed text-white rounded-lg transition-colors"
          >
            {isPending ? "Saving..." : "Mark as False Positive"}
          </button>
        </div>
      </div>
    </div>
  );
}
