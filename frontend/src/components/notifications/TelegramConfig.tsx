import { useState } from 'react';
import { AtSign, Eye, EyeOff, ExternalLink, Loader2 } from 'lucide-react';
import { HelpTooltip } from '@/components/HelpTooltip';

interface TelegramConfigProps {
  settings: Record<string, unknown>;
  onSettingChange: (key: string, value: boolean) => void;
  onTextChange: (key: string, value: string) => void;
  onTest: () => Promise<void>;
  testing: boolean;
  saving: boolean;
}

export function TelegramConfig({
  settings,
  onSettingChange,
  onTextChange,
  onTest,
  testing,
  saving,
}: TelegramConfigProps) {
  const [showBotToken, setShowBotToken] = useState(false);

  const isEnabled = settings.telegram_enabled === 'true' || settings.telegram_enabled === true;
  const botToken = (settings.telegram_bot_token as string) || '';
  const chatId = (settings.telegram_chat_id as string) || '';

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <AtSign className="w-6 h-6 text-blue-400" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">Telegram Configuration</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Send notifications via Telegram bot
            </p>
          </div>
        </div>
        <HelpTooltip content="Telegram bots can send messages to users, groups, or channels. Create a bot with @BotFather to get a token, then find your chat ID to receive notifications. Supports HTML formatting and inline buttons." />
      </div>

      <div className="space-y-4">
        {/* Enable Toggle */}
        <div>
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                Enable Telegram
              </span>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Send notifications via Telegram bot
              </p>
            </div>
            <div className="relative">
              <input
                type="checkbox"
                checked={isEnabled}
                onChange={(e) => onSettingChange('telegram_enabled', e.target.checked)}
                disabled={saving}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </div>
          </label>
        </div>

        {/* Bot Token */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            Bot Token
          </label>
          <div className="relative">
            <input
              type={showBotToken ? 'text' : 'password'}
              value={botToken}
              onChange={(e) => onTextChange('telegram_bot_token', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="123456789:ABC..."
              autoComplete="new-password"
              className="w-full px-3 py-2 pr-10 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
            <button
              type="button"
              onClick={() => setShowBotToken(!showBotToken)}
              disabled={!isEnabled}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text disabled:opacity-50"
            >
              {showBotToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-xs text-vuln-text-disabled mt-1">
            Bot token from @BotFather
          </p>
        </div>

        {/* Chat ID */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            Chat ID
          </label>
          <input
            type="text"
            value={chatId}
            onChange={(e) => onTextChange('telegram_chat_id', e.target.value)}
            disabled={!isEnabled || saving}
            placeholder="-1001234567890"
            autoComplete="off"
            className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          />
          <p className="text-xs text-vuln-text-disabled mt-1">
            User, group, or channel ID (use @userinfobot to find your ID)
          </p>
        </div>

        {/* Test Button */}
        <button
          onClick={onTest}
          disabled={!isEnabled || testing || !botToken || !chatId}
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
        <div className="bg-blue-400/10 border border-blue-400/20 rounded-lg p-3">
          <div className="flex items-start gap-2">
            <ExternalLink className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-vuln-text-muted">
              <strong className="text-blue-400">Setup:</strong> Message @BotFather to create a bot and get a token. Start a chat with your bot, then use @userinfobot to find your chat ID. For groups, add the bot to the group first.{' '}
              <a
                href="https://core.telegram.org/bots#how-do-i-create-a-bot"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:underline"
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
