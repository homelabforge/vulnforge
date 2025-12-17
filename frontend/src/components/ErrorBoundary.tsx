/**
 * Error Boundary - Catch and display runtime errors gracefully
 */

import { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RefreshCw, Copy, Check, ChevronDown, ChevronUp } from "lucide-react";
import { formatErrorDetails } from "@/lib/errorHandler";
import { ApiError } from "@/lib/api";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  copied: boolean;
  showDetails: boolean;
}

// Check if we're in development mode
const isDevelopment = import.meta.env.DEV;

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
    copied: false,
    showDetails: isDevelopment, // Auto-expand in dev mode
  };

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return {
      hasError: true,
      error,
      errorInfo: null,
    };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught error:", error, errorInfo);
    this.setState({
      error,
      errorInfo,
    });
  }

  private handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      copied: false,
      showDetails: isDevelopment,
    });
    window.location.href = "/";
  };

  private handleCopyError = async () => {
    const { error, errorInfo } = this.state;
    if (!error) return;

    const errorReport = [
      "=== VulnForge Error Report ===",
      `Timestamp: ${new Date().toISOString()}`,
      `URL: ${window.location.href}`,
      `User Agent: ${navigator.userAgent}`,
      "",
      "--- Error ---",
      error.toString(),
      "",
      error.stack ? `--- Stack Trace ---\n${error.stack}` : "",
      "",
      errorInfo?.componentStack ? `--- Component Stack ---${errorInfo.componentStack}` : "",
    ].filter(Boolean).join("\n");

    try {
      await navigator.clipboard.writeText(errorReport);
      this.setState({ copied: true });
      setTimeout(() => this.setState({ copied: false }), 2000);
    } catch (err) {
      console.error("Failed to copy error:", err);
    }
  };

  private toggleDetails = () => {
    this.setState((prev) => ({ showDetails: !prev.showDetails }));
  };

  public render() {
    if (this.state.hasError) {
      const { error, errorInfo, copied, showDetails } = this.state;

      // Use formatErrorDetails for ApiErrors
      const formattedError = error ? formatErrorDetails(error) : null;
      const isApiError = error instanceof ApiError;

      return (
        <div className="min-h-screen bg-vuln-surface-light flex items-center justify-center p-4">
          <div className="max-w-2xl w-full bg-vuln-surface border border-red-500/30 rounded-lg p-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 bg-red-500/10 rounded-lg flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-red-500" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-vuln-text">
                  {formattedError?.title || "Something went wrong"}
                </h1>
                <p className="text-sm text-vuln-text-muted">
                  {isApiError ? "A server error occurred" : "An unexpected error occurred"}
                </p>
              </div>
            </div>

            {/* Error Summary */}
            {formattedError && (
              <div className="bg-vuln-surface-light border border-vuln-border rounded-lg p-4 mb-4">
                <p className="text-vuln-text">{formattedError.message}</p>

                {/* Suggestions from API errors */}
                {formattedError.suggestions && formattedError.suggestions.length > 0 && (
                  <div className="mt-3 p-3 bg-blue-500/10 border border-blue-500/30 rounded">
                    <p className="text-sm text-blue-300 font-medium mb-1">Suggestions:</p>
                    <ul className="text-sm text-blue-200 list-disc list-inside">
                      {formattedError.suggestions.map((suggestion, i) => (
                        <li key={i}>{suggestion}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Retryable indicator */}
                {formattedError.isRetryable && (
                  <p className="mt-2 text-sm text-green-400">
                    This error may be temporary. Try reloading the page.
                  </p>
                )}
              </div>
            )}

            {/* Expandable Technical Details */}
            {error && (isDevelopment || errorInfo) && (
              <div className="mb-4">
                <button
                  onClick={this.toggleDetails}
                  className="flex items-center gap-2 text-sm text-vuln-text-muted hover:text-vuln-text transition-colors"
                >
                  {showDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  Technical Details {isDevelopment && <span className="text-xs text-yellow-500">(Dev Mode)</span>}
                </button>

                {showDetails && (
                  <div className="mt-3 bg-vuln-surface-light border border-vuln-border rounded-lg p-4">
                    <p className="text-sm font-semibold text-red-400 mb-2">Error:</p>
                    <p className="text-sm text-vuln-text font-mono break-all">
                      {error.toString()}
                    </p>

                    {error.stack && isDevelopment && (
                      <details className="mt-3">
                        <summary className="text-sm text-vuln-text-muted cursor-pointer hover:text-vuln-text">
                          Stack Trace
                        </summary>
                        <pre className="mt-2 text-xs text-vuln-text-disabled overflow-x-auto whitespace-pre-wrap">
                          {error.stack}
                        </pre>
                      </details>
                    )}

                    {errorInfo && (
                      <details className="mt-3">
                        <summary className="text-sm text-vuln-text-muted cursor-pointer hover:text-vuln-text">
                          Component Stack
                        </summary>
                        <pre className="mt-2 text-xs text-vuln-text-disabled overflow-x-auto whitespace-pre-wrap">
                          {errorInfo.componentStack}
                        </pre>
                      </details>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex flex-wrap gap-3">
              <button
                onClick={this.handleReset}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                Return to Dashboard
              </button>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-vuln-surface-light hover:bg-vuln-border text-vuln-text rounded-lg transition-colors"
              >
                Reload Page
              </button>
              <button
                onClick={this.handleCopyError}
                className="flex items-center gap-2 px-4 py-2 bg-vuln-surface-light hover:bg-vuln-border text-vuln-text rounded-lg transition-colors"
              >
                {copied ? (
                  <>
                    <Check className="w-4 h-4 text-green-500" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="w-4 h-4" />
                    Copy Error
                  </>
                )}
              </button>
            </div>

            <div className="mt-6 p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg">
              <p className="text-sm text-amber-300">
                <strong>Tip:</strong> If this error persists, try clearing your browser cache or
                use "Copy Error" to share details when reporting issues.
              </p>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
