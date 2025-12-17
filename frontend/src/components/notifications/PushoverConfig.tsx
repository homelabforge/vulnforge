import { useState } from 'react';
import { Send, Eye, EyeOff, ExternalLink, Loader2 } from 'lucide-react';
import { HelpTooltip } from '@/components/HelpTooltip';

interface PushoverConfigProps {
  settings: Record<string, unknown>;
  onSettingChange: (key: string, value: boolean) => void;
  onTextChange: (key: string, value: string) => void;
  onTest: () => Promise<void>;
  testing: boolean;
  saving: boolean;
}

export function PushoverConfig({
  settings,
  onSettingChange,
  onTextChange,
  onTest,
  testing,
  saving,
}: PushoverConfigProps) {
  const [showUserKey, setShowUserKey] = useState(false);
  const [showApiToken, setShowApiToken] = useState(false);

  const isEnabled = settings.pushover_enabled === 'true' || settings.pushover_enabled === true;
  const userKey = (settings.pushover_user_key as string) || '';
  const apiToken = (settings.pushover_api_token as string) || '';

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <Send className="w-6 h-6 text-cyan-500" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">Pushover Configuration</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Cross-platform push notifications
            </p>
          </div>
        </div>
        <HelpTooltip content="Pushover delivers notifications to iOS, Android, and desktop. It's a paid service ($5 one-time per platform) with a reliable infrastructure and priority levels including emergency alerts." />
      </div>

      <div className="space-y-4">
        {/* Enable Toggle */}
        <div>
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                Enable Pushover
              </span>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Send notifications via Pushover
              </p>
            </div>
            <div className="relative">
              <input
                type="checkbox"
                checked={isEnabled}
                onChange={(e) => onSettingChange('pushover_enabled', e.target.checked)}
                disabled={saving}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </div>
          </label>
        </div>

        {/* User Key */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            User Key
          </label>
          <div className="relative">
            <input
              type={showUserKey ? 'text' : 'password'}
              value={userKey}
              onChange={(e) => onTextChange('pushover_user_key', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="u..."
              autoComplete="new-password"
              className="w-full px-3 py-2 pr-10 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
            <button
              type="button"
              onClick={() => setShowUserKey(!showUserKey)}
              disabled={!isEnabled}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text disabled:opacity-50"
            >
              {showUserKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-xs text-vuln-text-disabled mt-1">
            Your Pushover user key (found on the Pushover dashboard)
          </p>
        </div>

        {/* API Token */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            API Token
          </label>
          <div className="relative">
            <input
              type={showApiToken ? 'text' : 'password'}
              value={apiToken}
              onChange={(e) => onTextChange('pushover_api_token', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="a..."
              autoComplete="new-password"
              className="w-full px-3 py-2 pr-10 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
            <button
              type="button"
              onClick={() => setShowApiToken(!showApiToken)}
              disabled={!isEnabled}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text disabled:opacity-50"
            >
              {showApiToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-xs text-vuln-text-disabled mt-1">
            Application API token (create an app at pushover.net)
          </p>
        </div>

        {/* Test Button */}
        <button
          onClick={onTest}
          disabled={!isEnabled || testing || !userKey || !apiToken}
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
        <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-lg p-3">
          <div className="flex items-start gap-2">
            <ExternalLink className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-vuln-text-muted">
              <strong className="text-cyan-400">Setup:</strong> Create a Pushover account, then register an application to get an API token. Your user key is on the main dashboard.{' '}
              <a
                href="https://pushover.net"
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:underline"
              >
                Get started
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
