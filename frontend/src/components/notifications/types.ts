/**
 * Typed notification settings interface.
 *
 * Replaces `Record<string, unknown>` across all notification config components.
 * All values are their actual runtime types (boolean for toggles, string for text).
 */

export interface NotificationSettings {
  // Ntfy
  ntfy_enabled: boolean;
  ntfy_server: string;
  ntfy_topic: string;
  ntfy_token: string;
  // Gotify
  gotify_enabled: boolean;
  gotify_server: string;
  gotify_token: string;
  // Pushover
  pushover_enabled: boolean;
  pushover_user_key: string;
  pushover_api_token: string;
  // Slack
  slack_enabled: boolean;
  slack_webhook_url: string;
  // Discord
  discord_enabled: boolean;
  discord_webhook_url: string;
  // Telegram
  telegram_enabled: boolean;
  telegram_bot_token: string;
  telegram_chat_id: string;
  // Email
  email_enabled: boolean;
  email_smtp_host: string;
  email_smtp_port: string;
  email_smtp_user: string;
  email_smtp_password: string;
  email_smtp_tls: boolean;
  email_from: string;
  email_to: string;
  // Event notification groups
  notify_security_enabled: boolean;
  notify_security_kev: boolean;
  notify_security_critical: boolean;
  notify_security_secrets: boolean;
  notify_scans_enabled: boolean;
  notify_scans_complete: boolean;
  notify_scans_failed: boolean;
  notify_scans_compliance_complete: boolean;
  notify_scans_compliance_failures: boolean;
  notify_system_enabled: boolean;
  notify_system_kev_refresh: boolean;
  notify_system_backup: boolean;
  // Advanced (optional — not always present in the settings object)
  notification_retry_attempts?: string;
  notification_retry_delay?: string;
}
