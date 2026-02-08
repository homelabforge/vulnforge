import { useState } from 'react';
import { MessageSquare, Eye, EyeOff, ExternalLink } from 'lucide-react';
import { HelpTooltip } from '@/components/HelpTooltip';
import { Toggle } from '@/components/Toggle';
import { TestConnectionButton } from './TestConnectionButton';
import type { NotificationSettings } from './types';

interface DiscordConfigProps {
  settings: NotificationSettings;
  onSettingChange: (key: string, value: boolean) => void;
  onTextChange: (key: string, value: string) => void;
  onTest: () => Promise<void>;
  testing: boolean;
  saving: boolean;
}

export function DiscordConfig({
  settings,
  onSettingChange,
  onTextChange,
  onTest,
  testing,
  saving,
}: DiscordConfigProps) {
  const [showWebhook, setShowWebhook] = useState(false);

  const isEnabled = settings.discord_enabled;
  const webhookUrl = settings.discord_webhook_url;

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <MessageSquare className="w-6 h-6 text-indigo-500" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">Discord Configuration</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Send notifications to Discord channels
            </p>
          </div>
        </div>
        <HelpTooltip content="Discord webhooks post messages to any channel. VulnForge sends rich embeds with color-coded severity levels. Create a webhook in your channel settings to get started." />
      </div>

      <div className="space-y-4">
        {/* Enable Toggle */}
        <div>
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                Enable Discord
              </span>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Send notifications to a Discord channel
              </p>
            </div>
            <Toggle checked={isEnabled} onChange={(v) => onSettingChange('discord_enabled', v)} disabled={saving} />
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
              onChange={(e) => onTextChange('discord_webhook_url', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="https://discord.com/api/webhooks/..."
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
            Webhook URL from your Discord channel settings
          </p>
        </div>

        <TestConnectionButton onTest={onTest} testing={testing} disabled={!isEnabled || !webhookUrl} />

        {/* Info Box */}
        <div className="bg-indigo-500/10 border border-indigo-500/20 rounded-lg p-3">
          <div className="flex items-start gap-2">
            <ExternalLink className="w-4 h-4 text-indigo-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-vuln-text-muted">
              <strong className="text-indigo-400">Setup:</strong> In Discord, right-click a channel &gt; Edit Channel &gt; Integrations &gt; Webhooks. Create a new webhook and copy the URL.{' '}
              <a
                href="https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks"
                target="_blank"
                rel="noopener noreferrer"
                className="text-indigo-400 hover:underline"
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
