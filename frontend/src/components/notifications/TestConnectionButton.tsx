/**
 * TestConnectionButton - Shared test button for notification service configs.
 */

import { Loader2 } from "lucide-react";

interface TestConnectionButtonProps {
  onTest: () => Promise<void>;
  testing: boolean;
  disabled: boolean;
}

export function TestConnectionButton({ onTest, testing, disabled }: TestConnectionButtonProps): React.ReactElement {
  return (
    <button
      onClick={onTest}
      disabled={disabled || testing}
      className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
    >
      {testing ? (
        <>
          <Loader2 className="w-4 h-4 animate-spin" />
          Testing...
        </>
      ) : (
        'Test Connection'
      )}
    </button>
  );
}
