import { useState } from 'react';
import { Mail, Eye, EyeOff, ExternalLink } from 'lucide-react';
import { HelpTooltip } from '@/components/HelpTooltip';
import { Toggle } from '@/components/Toggle';
import { TestConnectionButton } from './TestConnectionButton';
import type { NotificationSettings } from './types';

interface EmailConfigProps {
  settings: NotificationSettings;
  onSettingChange: (key: string, value: boolean) => void;
  onTextChange: (key: string, value: string) => void;
  onTest: () => Promise<void>;
  testing: boolean;
  saving: boolean;
}

export function EmailConfig({
  settings,
  onSettingChange,
  onTextChange,
  onTest,
  testing,
  saving,
}: EmailConfigProps) {
  const [showPassword, setShowPassword] = useState(false);

  const isEnabled = settings.email_enabled;
  const smtpHost = settings.email_smtp_host;
  const smtpPort = settings.email_smtp_port || '587';
  const smtpUser = settings.email_smtp_user;
  const smtpPassword = settings.email_smtp_password;
  const smtpTls = settings.email_smtp_tls;
  const fromAddress = settings.email_from;
  const toAddress = settings.email_to;

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <Mail className="w-6 h-6 text-red-500" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">Email Configuration</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Send notifications via SMTP email
            </p>
          </div>
        </div>
        <HelpTooltip content="Send email notifications via SMTP. Works with any email provider (Gmail, Outlook, self-hosted). Emails include both plain text and HTML versions with severity-colored formatting." />
      </div>

      <div className="space-y-4">
        {/* Enable Toggle */}
        <div>
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                Enable Email
              </span>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Send notifications via SMTP email
              </p>
            </div>
            <Toggle checked={isEnabled} onChange={(v) => onSettingChange('email_enabled', v)} disabled={saving} />
          </label>
        </div>

        {/* SMTP Host & Port */}
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <label className="block text-sm font-medium text-vuln-text mb-2">
              SMTP Host
            </label>
            <input
              type="text"
              value={smtpHost}
              onChange={(e) => onTextChange('email_smtp_host', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="smtp.gmail.com"
              autoComplete="off"
              className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-vuln-text mb-2">
              Port
            </label>
            <input
              type="text"
              value={smtpPort}
              onChange={(e) => onTextChange('email_smtp_port', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="587"
              autoComplete="off"
              className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
          </div>
        </div>

        {/* SMTP User */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            SMTP Username
          </label>
          <input
            type="text"
            value={smtpUser}
            onChange={(e) => onTextChange('email_smtp_user', e.target.value)}
            disabled={!isEnabled || saving}
            placeholder="user@example.com"
            autoComplete="off"
            className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          />
        </div>

        {/* SMTP Password */}
        <div>
          <label className="block text-sm font-medium text-vuln-text mb-2">
            SMTP Password
          </label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              value={smtpPassword}
              onChange={(e) => onTextChange('email_smtp_password', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="App password or API key"
              autoComplete="new-password"
              className="w-full px-3 py-2 pr-10 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              disabled={!isEnabled}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text disabled:opacity-50"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* TLS Toggle */}
        <div>
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                Use STARTTLS
              </span>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Enable TLS encryption (recommended)
              </p>
            </div>
            <Toggle checked={smtpTls} onChange={(v) => onSettingChange('email_smtp_tls', v)} disabled={!isEnabled || saving} />
          </label>
        </div>

        {/* From/To Addresses */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-sm font-medium text-vuln-text mb-2">
              From Address
            </label>
            <input
              type="email"
              value={fromAddress}
              onChange={(e) => onTextChange('email_from', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="vulnforge@example.com"
              autoComplete="off"
              className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-vuln-text mb-2">
              To Address
            </label>
            <input
              type="email"
              value={toAddress}
              onChange={(e) => onTextChange('email_to', e.target.value)}
              disabled={!isEnabled || saving}
              placeholder="admin@example.com"
              autoComplete="off"
              className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text placeholder-vuln-text-disabled focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
          </div>
        </div>

        <TestConnectionButton onTest={onTest} testing={testing} disabled={!isEnabled || !smtpHost || !smtpUser || !smtpPassword || !fromAddress || !toAddress} />

        {/* Info Box */}
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
          <div className="flex items-start gap-2">
            <ExternalLink className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-vuln-text-muted">
              <strong className="text-red-400">Gmail users:</strong> Use an App Password instead of your account password. Go to Google Account &gt; Security &gt; 2-Step Verification &gt; App passwords.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
