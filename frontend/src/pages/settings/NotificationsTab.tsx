/**
 * NotificationsTab - All notification service configs + event notifications.
 *
 * Uses useSettingsForm to manage all notification settings as a single state
 * object instead of 30+ individual useState calls.
 */

import { useState } from "react";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { settingsApi } from "@/lib/api";
import { useSettingsForm, type SettingsFieldDef } from "@/hooks/useSettingsForm";
import {
  NotificationSubTabs,
  type NotificationSubTab,
  type NotificationSettings,
  EventNotificationsCard,
  NtfyConfig,
  GotifyConfig,
  PushoverConfig,
  SlackConfig,
  DiscordConfig,
  TelegramConfig,
  EmailConfig,
} from "@/components/notifications";

/** All notification settings field definitions. */
const NOTIFICATION_FIELDS: SettingsFieldDef[] = [
  // Service toggles + configs
  { key: "ntfy_enabled", type: "bool", defaultValue: true },
  { key: "ntfy_url", type: "string", defaultValue: "http://ntfy:80" },
  { key: "ntfy_topic", type: "string", defaultValue: "vulnforge" },
  { key: "ntfy_token", type: "string", defaultValue: "", sensitive: true },
  { key: "gotify_enabled", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "gotify_server", type: "string", defaultValue: "" },
  { key: "gotify_token", type: "string", defaultValue: "", sensitive: true },
  { key: "pushover_enabled", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "pushover_user_key", type: "string", defaultValue: "", sensitive: true },
  { key: "pushover_api_token", type: "string", defaultValue: "", sensitive: true },
  { key: "slack_enabled", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "slack_webhook_url", type: "string", defaultValue: "", sensitive: true },
  { key: "discord_enabled", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "discord_webhook_url", type: "string", defaultValue: "", sensitive: true },
  { key: "telegram_enabled", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "telegram_bot_token", type: "string", defaultValue: "", sensitive: true },
  { key: "telegram_chat_id", type: "string", defaultValue: "" },
  { key: "email_enabled", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "email_smtp_host", type: "string", defaultValue: "" },
  { key: "email_smtp_port", type: "string", defaultValue: "587" },
  { key: "email_smtp_user", type: "string", defaultValue: "" },
  { key: "email_smtp_password", type: "string", defaultValue: "", sensitive: true },
  { key: "email_smtp_tls", type: "bool", defaultValue: true },
  { key: "email_from", type: "string", defaultValue: "" },
  { key: "email_to", type: "string", defaultValue: "" },
  // Event notification toggles
  { key: "notify_security_enabled", type: "bool", defaultValue: true },
  { key: "notify_security_kev", type: "bool", defaultValue: true },
  { key: "notify_security_critical", type: "bool", defaultValue: true },
  { key: "notify_security_secrets", type: "bool", defaultValue: true },
  { key: "notify_scans_enabled", type: "bool", defaultValue: true },
  { key: "notify_scans_complete", type: "bool", defaultValue: true },
  { key: "notify_scans_failed", type: "bool", defaultValue: true },
  { key: "notify_scans_compliance_complete", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "notify_scans_compliance_failures", type: "bool", defaultValue: true },
  { key: "notify_system_enabled", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "notify_system_kev_refresh", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "notify_system_backup", type: "bool", defaultValue: false, boolDefault: "falsy" },
  // Advanced
  { key: "notification_retry_attempts", type: "string", defaultValue: "3" },
  { key: "notification_retry_delay", type: "string", defaultValue: "2.0" },
];

interface NotificationsTabProps {
  settingsMap: Record<string, string>;
  onSave: (payload: Record<string, string>) => void;
  isSaving: boolean;
}

export function NotificationsTab({ settingsMap, onSave, isSaving }: NotificationsTabProps): React.ReactElement {
  const [notificationSubTab, setNotificationSubTab] = useState<NotificationSubTab>("ntfy");
  const { values: rawValues, setBool, setText } = useSettingsForm(
    settingsMap,
    NOTIFICATION_FIELDS,
    onSave,
  );
  // Cast to NotificationSettings — field definitions guarantee the keys match
  const values = rawValues as unknown as NotificationSettings;

  // Test button states (UI-only, not persisted)
  const [testingService, setTestingService] = useState<string | null>(null);

  const testService = async (
    name: string,
    fn: () => Promise<{ success: boolean; message: string }>,
  ): Promise<void> => {
    setTestingService(name);
    try {
      const result = await fn();
      if (result.success) toast.success(result.message);
      else toast.error(result.message);
    } catch (error) {
      handleApiError(error, `Failed to test ${name} connection`);
    } finally {
      setTestingService(null);
    }
  };

  const hasAnyServiceEnabled =
    values.ntfy_enabled || values.gotify_enabled || values.pushover_enabled ||
    values.slack_enabled || values.discord_enabled || values.telegram_enabled ||
    values.email_enabled;

  const configProps = {
    settings: values,
    onSettingChange: setBool,
    onTextChange: setText,
    saving: isSaving,
  };

  return (
    <div className="space-y-6">
      <NotificationSubTabs
        activeSubTab={notificationSubTab}
        onSubTabChange={setNotificationSubTab}
        enabledServices={{
          ntfy: values.ntfy_enabled, gotify: values.gotify_enabled, pushover: values.pushover_enabled,
          slack: values.slack_enabled, discord: values.discord_enabled, telegram: values.telegram_enabled, email: values.email_enabled,
        }}
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          {notificationSubTab === "ntfy" && <NtfyConfig {...configProps} onTest={() => testService("ntfy", settingsApi.testNtfy)} testing={testingService === "ntfy"} />}
          {notificationSubTab === "gotify" && <GotifyConfig {...configProps} onTest={() => testService("Gotify", settingsApi.testGotify)} testing={testingService === "gotify"} />}
          {notificationSubTab === "pushover" && <PushoverConfig {...configProps} onTest={() => testService("Pushover", settingsApi.testPushover)} testing={testingService === "pushover"} />}
          {notificationSubTab === "slack" && <SlackConfig {...configProps} onTest={() => testService("Slack", settingsApi.testSlack)} testing={testingService === "slack"} />}
          {notificationSubTab === "discord" && <DiscordConfig {...configProps} onTest={() => testService("Discord", settingsApi.testDiscord)} testing={testingService === "discord"} />}
          {notificationSubTab === "telegram" && <TelegramConfig {...configProps} onTest={() => testService("Telegram", settingsApi.testTelegram)} testing={testingService === "telegram"} />}
          {notificationSubTab === "email" && <EmailConfig {...configProps} onTest={() => testService("email", settingsApi.testEmail)} testing={testingService === "email"} />}
        </div>

        <EventNotificationsCard
          settings={values}
          onSettingChange={setBool}
          onTextChange={setText}
          saving={isSaving}
          hasEnabledService={hasAnyServiceEnabled}
        />
      </div>
    </div>
  );
}
