import { useState } from 'react';
import { Hash, Eye, EyeOff, ExternalLink, Loader2 } from 'lucide-react';
import { HelpTooltip } from '@/components/HelpTooltip';

interface SlackConfigProps {
  settings: Record<string, unknown>;
  onSettingChange: (key: string, value: boolean) => void;
  onTextChange: (key: string, value: string) => void;
  onTest: () => Promise<void>;
  testing: boolean;
  saving: boolean;
}

export function SlackConfig({
  settings,
  onSettingChange,
  onTextChange,
  onTest,
  testing,
  saving,
}: SlackConfigProps) {
  const [showWebhook, setShowWebhook] = useState(false);

  const isEnabled = settings.slack_enabled === 'true' || settings.slack_enabled === true;
  const webhookUrl = (settings.slack_webhook_url as string) || '';

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <Hash className="w-6 h-6 text-green-500" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">Slack Configuration</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Send notifications to Slack channels
            </p>
          </div>
        </div>
        <HelpTooltip content="Slack incoming webhooks let you post messages to any channel. Create a webhook URL in your Slack workspace settings, and VulnForge will send formatted notifications with severity-colored attachments." />
      </div>

      <div className="space-y-4">
        {/* Enable Toggle */}
        <div>
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                Enable Slack
              </span>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Send notifications to a Slack channel
              </p>
            </div>
            <div className="relative">
              <input
                type="checkbox"
                checked={isEnabled}
                onChange={(e) => onSettingChange('slack_enabled', e.target.checked)}
                disabled={saving}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </div>
          </label>
        </div>

        {/* Webhook URL */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            Webhook URL
          </label>
          <div className="relative">
            <input
              type={showWebhook ? 'text' : 'password'}
              value={webhookUrl}
              onChange={(e) => onTextChange('slack_webhook_url', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="https://hooks.slack.com/services/..."
              autoComplete="new-password"
              className="w-full px-3 py-2 pr-10 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
            <button
              type="button"
              onClick={() => setShowWebhook(!showWebhook)}
              disabled={!isEnabled}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text disabled:opacity-50"
            >
              {showWebhook ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-xs text-vuln-text-disabled mt-1">
            Incoming webhook URL from your Slack workspace
          </p>
        </div>

        {/* Test Button */}
        <button
          onClick={onTest}
          disabled={!isEnabled || testing || !webhookUrl}
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
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-3">
          <div className="flex items-start gap-2">
            <ExternalLink className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-vuln-text-muted">
              <strong className="text-green-400">Setup:</strong> In Slack, go to Settings &gt; Manage Apps &gt; Incoming Webhooks. Create a new webhook and select the channel for VulnForge notifications.{' '}
              <a
                href="https://api.slack.com/messaging/webhooks"
                target="_blank"
                rel="noopener noreferrer"
                className="text-green-400 hover:underline"
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
