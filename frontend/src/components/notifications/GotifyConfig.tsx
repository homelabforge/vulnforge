import { useState } from 'react';
import { Radio, Eye, EyeOff, ExternalLink } from 'lucide-react';
import { HelpTooltip } from '@/components/HelpTooltip';
import { Toggle } from '@/components/Toggle';
import { TestConnectionButton } from './TestConnectionButton';
import type { NotificationSettings } from './types';

interface GotifyConfigProps {
  settings: NotificationSettings;
  onSettingChange: (key: string, value: boolean) => void;
  onTextChange: (key: string, value: string) => void;
  onTest: () => Promise<void>;
  testing: boolean;
  saving: boolean;
}

export function GotifyConfig({
  settings,
  onSettingChange,
  onTextChange,
  onTest,
  testing,
  saving,
}: GotifyConfigProps) {
  const [showToken, setShowToken] = useState(false);

  const isEnabled = settings.gotify_enabled;
  const serverUrl = settings.gotify_server;
  const token = settings.gotify_token;

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <Radio className="w-6 h-6 text-orange-500" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">Gotify Configuration</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Self-hosted push notification server
            </p>
          </div>
        </div>
        <HelpTooltip content="Gotify is a self-hosted push notification service. Create an application in your Gotify server to get an app token, then use the Gotify app on your phone to receive notifications." />
      </div>

      <div className="space-y-4">
        {/* Enable Toggle */}
        <div>
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                Enable Gotify
              </span>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Send notifications via Gotify server
              </p>
            </div>
            <Toggle checked={isEnabled} onChange={(v) => onSettingChange('gotify_enabled', v)} disabled={saving} />
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
            onChange={(e) => onTextChange('gotify_server', e.target.value)}
            disabled={!isEnabled || saving}
            placeholder="https://gotify.example.com"
            autoComplete="off"
            className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          />
          <p className="text-xs text-vuln-text-disabled mt-1">
            URL of your Gotify server
          </p>
        </div>

        {/* App Token */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            App Token
          </label>
          <div className="relative">
            <input
              type={showToken ? 'text' : 'password'}
              value={token}
              onChange={(e) => onTextChange('gotify_token', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="A..."
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
            Application token from your Gotify server (Apps &gt; Create Application)
          </p>
        </div>

        <TestConnectionButton onTest={onTest} testing={testing} disabled={!isEnabled || !serverUrl || !token} />

        {/* Info Box */}
        <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg p-3">
          <div className="flex items-start gap-2">
            <ExternalLink className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-vuln-text-muted">
              <strong className="text-orange-400">Setup:</strong> In Gotify, go to Apps and create a new application for VulnForge. Copy the app token and paste it above.{' '}
              <a
                href="https://gotify.net/docs/index"
                target="_blank"
                rel="noopener noreferrer"
                className="text-orange-400 hover:underline"
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
