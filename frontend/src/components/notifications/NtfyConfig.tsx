import { useState } from 'react';
import { Bell, Eye, EyeOff, ExternalLink, Loader2 } from 'lucide-react';
import { HelpTooltip } from '@/components/HelpTooltip';

interface NtfyConfigProps {
  settings: Record<string, unknown>;
  onSettingChange: (key: string, value: boolean) => void;
  onTextChange: (key: string, value: string) => void;
  onTest: () => Promise<void>;
  testing: boolean;
  saving: boolean;
}

export function NtfyConfig({
  settings,
  onSettingChange,
  onTextChange,
  onTest,
  testing,
  saving,
}: NtfyConfigProps) {
  const [showToken, setShowToken] = useState(false);

  const isEnabled = settings.ntfy_enabled === 'true' || settings.ntfy_enabled === true;
  const serverUrl = (settings.ntfy_server as string) || '';
  const topic = (settings.ntfy_topic as string) || '';
  const token = (settings.ntfy_token as string) || '';

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <Bell className="w-6 h-6 text-purple-500" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">ntfy Configuration</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Self-hosted or ntfy.sh push notifications
            </p>
          </div>
        </div>
        <HelpTooltip content="ntfy is a simple pub-sub notification service. You can self-host it or use ntfy.sh. Subscribe to your topic on your phone to receive push notifications." />
      </div>

      <div className="space-y-4">
        {/* Enable Toggle */}
        <div>
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                Enable ntfy
              </span>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Send notifications via ntfy server
              </p>
            </div>
            <div className="relative">
              <input
                type="checkbox"
                checked={isEnabled}
                onChange={(e) => onSettingChange('ntfy_enabled', e.target.checked)}
                disabled={saving}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </div>
          </label>
        </div>

        {/* Server URL */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            Server URL
          </label>
          <input
            type="text"
            value={serverUrl}
            onChange={(e) => onTextChange('ntfy_server', e.target.value)}
            disabled={!isEnabled || saving}
            placeholder="https://ntfy.sh"
            autoComplete="off"
            className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          />
          <p className="text-xs text-vuln-text-disabled mt-1">
            URL of your ntfy server (e.g., https://ntfy.sh or http://ntfy:80)
          </p>
        </div>

        {/* Topic */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            Topic
          </label>
          <input
            type="text"
            value={topic}
            onChange={(e) => onTextChange('ntfy_topic', e.target.value)}
            disabled={!isEnabled || saving}
            placeholder="vulnforge"
            autoComplete="off"
            className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          />
          <p className="text-xs text-vuln-text-disabled mt-1">
            Topic name for notifications (use a unique, hard-to-guess name)
          </p>
        </div>

        {/* Access Token */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            Access Token <span className="text-vuln-text-disabled">(optional)</span>
          </label>
          <div className="relative">
            <input
              type={showToken ? 'text' : 'password'}
              value={token}
              onChange={(e) => onTextChange('ntfy_token', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="tk_..."
              autoComplete="new-password"
              className="w-full px-3 py-2 pr-10 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
            <button
              type="button"
              onClick={() => setShowToken(!showToken)}
              disabled={!isEnabled}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text disabled:opacity-50"
            >
              {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-xs text-vuln-text-disabled mt-1">
            Required if your ntfy server has authentication enabled
          </p>
        </div>

        {/* Test Button */}
        <button
          onClick={onTest}
          disabled={!isEnabled || testing || !serverUrl || !topic}
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

        {/* Info Box */}
        <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-3">
          <div className="flex items-start gap-2">
            <ExternalLink className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-vuln-text-muted">
              <strong className="text-purple-400">Setup:</strong> Install the ntfy app on your phone, then subscribe to your topic. You'll receive push notifications for all VulnForge events.{' '}
              <a
                href="https://ntfy.sh"
                target="_blank"
                rel="noopener noreferrer"
                className="text-purple-400 hover:underline"
              >
                Learn more
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
