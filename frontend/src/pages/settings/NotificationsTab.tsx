/**
 * NotificationsTab - All notification service configs + event notifications.
 */

import { useState } from "react";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { settingsApi } from "@/lib/api";
import { useAutoSave } from "@/hooks/useAutoSave";
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

interface NotificationsTabProps {
  settingsMap: Record<string, string>;
  onSave: (payload: Record<string, string>) => void;
  isSaving: boolean;
}

export function NotificationsTab({ settingsMap, onSave, isSaving }: NotificationsTabProps): React.ReactElement {
  const [notificationSubTab, setNotificationSubTab] = useState<NotificationSubTab>("ntfy");

  // --- Service settings ---
  const [ntfyEnabled, setNtfyEnabled] = useState(settingsMap.ntfy_enabled !== "false");
  const [ntfyUrl, setNtfyUrl] = useState(settingsMap.ntfy_url || "http://ntfy:80");
  const [ntfyTopic, setNtfyTopic] = useState(settingsMap.ntfy_topic || "vulnforge");
  const [ntfyToken, setNtfyToken] = useState(settingsMap.ntfy_token || "");
  // Legacy ntfy thresholds (no UI — forwarded to keep backend values intact)
  const notifyOnScanComplete = settingsMap.notify_on_scan_complete !== "false";
  const notifyOnCritical = settingsMap.notify_on_critical !== "false";
  const notifyThresholdCritical = Number(settingsMap.notify_threshold_critical) || 1;
  const notifyThresholdHigh = Number(settingsMap.notify_threshold_high) || 10;

  const [gotifyEnabled, setGotifyEnabled] = useState(settingsMap.gotify_enabled === "true");
  const [gotifyServer, setGotifyServer] = useState(settingsMap.gotify_server || "");
  const [gotifyToken, setGotifyToken] = useState(settingsMap.gotify_token || "");

  const [pushoverEnabled, setPushoverEnabled] = useState(settingsMap.pushover_enabled === "true");
  const [pushoverUserKey, setPushoverUserKey] = useState(settingsMap.pushover_user_key || "");
  const [pushoverApiToken, setPushoverApiToken] = useState(settingsMap.pushover_api_token || "");

  const [slackEnabled, setSlackEnabled] = useState(settingsMap.slack_enabled === "true");
  const [slackWebhookUrl, setSlackWebhookUrl] = useState(settingsMap.slack_webhook_url || "");

  const [discordEnabled, setDiscordEnabled] = useState(settingsMap.discord_enabled === "true");
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState(settingsMap.discord_webhook_url || "");

  const [telegramEnabled, setTelegramEnabled] = useState(settingsMap.telegram_enabled === "true");
  const [telegramBotToken, setTelegramBotToken] = useState(settingsMap.telegram_bot_token || "");
  const [telegramChatId, setTelegramChatId] = useState(settingsMap.telegram_chat_id || "");

  const [emailEnabled, setEmailEnabled] = useState(settingsMap.email_enabled === "true");
  const [emailSmtpHost, setEmailSmtpHost] = useState(settingsMap.email_smtp_host || "");
  const [emailSmtpPort, setEmailSmtpPort] = useState(settingsMap.email_smtp_port || "587");
  const [emailSmtpUser, setEmailSmtpUser] = useState(settingsMap.email_smtp_user || "");
  const [emailSmtpPassword, setEmailSmtpPassword] = useState(settingsMap.email_smtp_password || "");
  const [emailSmtpTls, setEmailSmtpTls] = useState(settingsMap.email_smtp_tls !== "false");
  const [emailFrom, setEmailFrom] = useState(settingsMap.email_from || "");
  const [emailTo, setEmailTo] = useState(settingsMap.email_to || "");

  // --- Event notification settings ---
  const [notifySecurityEnabled, setNotifySecurityEnabled] = useState(settingsMap.notify_security_enabled !== "false");
  const [notifySecurityKev, setNotifySecurityKev] = useState(settingsMap.notify_security_kev !== "false");
  const [notifySecurityCritical, setNotifySecurityCritical] = useState(settingsMap.notify_security_critical !== "false");
  const [notifySecuritySecrets, setNotifySecuritySecrets] = useState(settingsMap.notify_security_secrets !== "false");
  const [notifyScansEnabled, setNotifyScansEnabled] = useState(settingsMap.notify_scans_enabled !== "false");
  const [notifyScansComplete, setNotifyScansComplete] = useState(settingsMap.notify_scans_complete !== "false");
  const [notifyScansFailed, setNotifyScansFailed] = useState(settingsMap.notify_scans_failed !== "false");
  const [notifyScansComplianceComplete, setNotifyScansComplianceComplete] = useState(settingsMap.notify_scans_compliance_complete !== "false");
  const [notifyScansComplianceFailures, setNotifyScansComplianceFailures] = useState(settingsMap.notify_scans_compliance_failures !== "false");
  const [notifySystemEnabled, setNotifySystemEnabled] = useState(settingsMap.notify_system_enabled === "true");
  const [notifySystemKevRefresh, setNotifySystemKevRefresh] = useState(settingsMap.notify_system_kev_refresh === "true");
  const [notifySystemBackup, setNotifySystemBackup] = useState(settingsMap.notify_system_backup === "true");

  // --- Test button states ---
  const [testingNtfy, setTestingNtfy] = useState(false);
  const [testingGotify, setTestingGotify] = useState(false);
  const [testingPushover, setTestingPushover] = useState(false);
  const [testingSlack, setTestingSlack] = useState(false);
  const [testingDiscord, setTestingDiscord] = useState(false);
  const [testingTelegram, setTestingTelegram] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);

  // --- Auto-save ---
  useAutoSave(
    () => ({
      ntfy_enabled: ntfyEnabled.toString(),
      ntfy_url: ntfyUrl,
      ntfy_topic: ntfyTopic,
      ntfy_token: ntfyToken,
      notify_on_scan_complete: notifyOnScanComplete.toString(),
      notify_on_critical: notifyOnCritical.toString(),
      notify_threshold_critical: notifyThresholdCritical.toString(),
      notify_threshold_high: notifyThresholdHigh.toString(),
      gotify_enabled: gotifyEnabled.toString(),
      gotify_server: gotifyServer,
      gotify_token: gotifyToken,
      pushover_enabled: pushoverEnabled.toString(),
      pushover_user_key: pushoverUserKey,
      pushover_api_token: pushoverApiToken,
      slack_enabled: slackEnabled.toString(),
      slack_webhook_url: slackWebhookUrl,
      discord_enabled: discordEnabled.toString(),
      discord_webhook_url: discordWebhookUrl,
      telegram_enabled: telegramEnabled.toString(),
      telegram_bot_token: telegramBotToken,
      telegram_chat_id: telegramChatId,
      email_enabled: emailEnabled.toString(),
      email_smtp_host: emailSmtpHost,
      email_smtp_port: emailSmtpPort,
      email_smtp_user: emailSmtpUser,
      email_smtp_password: emailSmtpPassword,
      email_smtp_tls: emailSmtpTls.toString(),
      email_from: emailFrom,
      email_to: emailTo,
      notify_security_enabled: notifySecurityEnabled.toString(),
      notify_security_kev: notifySecurityKev.toString(),
      notify_security_critical: notifySecurityCritical.toString(),
      notify_security_secrets: notifySecuritySecrets.toString(),
      notify_scans_enabled: notifyScansEnabled.toString(),
      notify_scans_complete: notifyScansComplete.toString(),
      notify_scans_failed: notifyScansFailed.toString(),
      notify_scans_compliance_complete: notifyScansComplianceComplete.toString(),
      notify_scans_compliance_failures: notifyScansComplianceFailures.toString(),
      notify_system_enabled: notifySystemEnabled.toString(),
      notify_system_kev_refresh: notifySystemKevRefresh.toString(),
      notify_system_backup: notifySystemBackup.toString(),
    }),
    onSave,
    [
      ntfyEnabled, ntfyUrl, ntfyTopic, ntfyToken, notifyOnScanComplete, notifyOnCritical,
      notifyThresholdCritical, notifyThresholdHigh,
      gotifyEnabled, gotifyServer, gotifyToken,
      pushoverEnabled, pushoverUserKey, pushoverApiToken,
      slackEnabled, slackWebhookUrl,
      discordEnabled, discordWebhookUrl,
      telegramEnabled, telegramBotToken, telegramChatId,
      emailEnabled, emailSmtpHost, emailSmtpPort, emailSmtpUser, emailSmtpPassword, emailSmtpTls, emailFrom, emailTo,
      notifySecurityEnabled, notifySecurityKev, notifySecurityCritical, notifySecuritySecrets,
      notifyScansEnabled, notifyScansComplete, notifyScansFailed,
      notifyScansComplianceComplete, notifyScansComplianceFailures,
      notifySystemEnabled, notifySystemKevRefresh, notifySystemBackup,
    ],
    true,
  );

  // --- Test handlers ---
  const testService = async (
    name: string,
    fn: () => Promise<{ success: boolean; message: string }>,
    setTesting: (v: boolean) => void,
  ): Promise<void> => {
    setTesting(true);
    try {
      const result = await fn();
      if (result.success) toast.success(result.message);
      else toast.error(result.message);
    } catch (error) {
      handleApiError(error, `Failed to test ${name} connection`);
    } finally {
      setTesting(false);
    }
  };

  // --- Settings map for notification components ---
  const notificationSettings: NotificationSettings = {
    ntfy_enabled: ntfyEnabled, ntfy_server: ntfyUrl, ntfy_topic: ntfyTopic, ntfy_token: ntfyToken,
    gotify_enabled: gotifyEnabled, gotify_server: gotifyServer, gotify_token: gotifyToken,
    pushover_enabled: pushoverEnabled, pushover_user_key: pushoverUserKey, pushover_api_token: pushoverApiToken,
    slack_enabled: slackEnabled, slack_webhook_url: slackWebhookUrl,
    discord_enabled: discordEnabled, discord_webhook_url: discordWebhookUrl,
    telegram_enabled: telegramEnabled, telegram_bot_token: telegramBotToken, telegram_chat_id: telegramChatId,
    email_enabled: emailEnabled, email_smtp_host: emailSmtpHost, email_smtp_port: emailSmtpPort,
    email_smtp_user: emailSmtpUser, email_smtp_password: emailSmtpPassword, email_smtp_tls: emailSmtpTls,
    email_from: emailFrom, email_to: emailTo,
    notify_security_enabled: notifySecurityEnabled, notify_security_kev: notifySecurityKev,
    notify_security_critical: notifySecurityCritical, notify_security_secrets: notifySecuritySecrets,
    notify_scans_enabled: notifyScansEnabled, notify_scans_complete: notifyScansComplete,
    notify_scans_failed: notifyScansFailed,
    notify_scans_compliance_complete: notifyScansComplianceComplete,
    notify_scans_compliance_failures: notifyScansComplianceFailures,
    notify_system_enabled: notifySystemEnabled, notify_system_kev_refresh: notifySystemKevRefresh,
    notify_system_backup: notifySystemBackup,
  };

  const handleBoolChange = (key: string, value: boolean): void => {
    const setters: Record<string, (v: boolean) => void> = {
      ntfy_enabled: setNtfyEnabled, gotify_enabled: setGotifyEnabled, pushover_enabled: setPushoverEnabled,
      slack_enabled: setSlackEnabled, discord_enabled: setDiscordEnabled, telegram_enabled: setTelegramEnabled,
      email_enabled: setEmailEnabled, email_smtp_tls: setEmailSmtpTls,
      notify_security_enabled: setNotifySecurityEnabled, notify_security_kev: setNotifySecurityKev,
      notify_security_critical: setNotifySecurityCritical, notify_security_secrets: setNotifySecuritySecrets,
      notify_scans_enabled: setNotifyScansEnabled, notify_scans_complete: setNotifyScansComplete,
      notify_scans_failed: setNotifyScansFailed,
      notify_scans_compliance_complete: setNotifyScansComplianceComplete,
      notify_scans_compliance_failures: setNotifyScansComplianceFailures,
      notify_system_enabled: setNotifySystemEnabled, notify_system_kev_refresh: setNotifySystemKevRefresh,
      notify_system_backup: setNotifySystemBackup,
    };
    setters[key]?.(value);
  };

  const handleTextChange = (key: string, value: string): void => {
    const setters: Record<string, (v: string) => void> = {
      ntfy_server: setNtfyUrl, ntfy_topic: setNtfyTopic, ntfy_token: setNtfyToken,
      gotify_server: setGotifyServer, gotify_token: setGotifyToken,
      pushover_user_key: setPushoverUserKey, pushover_api_token: setPushoverApiToken,
      slack_webhook_url: setSlackWebhookUrl,
      discord_webhook_url: setDiscordWebhookUrl,
      telegram_bot_token: setTelegramBotToken, telegram_chat_id: setTelegramChatId,
      email_smtp_host: setEmailSmtpHost, email_smtp_port: setEmailSmtpPort,
      email_smtp_user: setEmailSmtpUser, email_smtp_password: setEmailSmtpPassword,
      email_from: setEmailFrom, email_to: setEmailTo,
    };
    setters[key]?.(value);
  };

  const hasAnyServiceEnabled = ntfyEnabled || gotifyEnabled || pushoverEnabled ||
    slackEnabled || discordEnabled || telegramEnabled || emailEnabled;

  const configProps = {
    settings: notificationSettings,
    onSettingChange: handleBoolChange,
    onTextChange: handleTextChange,
    saving: isSaving,
  };

  return (
    <div className="space-y-6">
      <NotificationSubTabs
        activeSubTab={notificationSubTab}
        onSubTabChange={setNotificationSubTab}
        enabledServices={{
          ntfy: ntfyEnabled, gotify: gotifyEnabled, pushover: pushoverEnabled,
          slack: slackEnabled, discord: discordEnabled, telegram: telegramEnabled, email: emailEnabled,
        }}
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          {notificationSubTab === "ntfy" && <NtfyConfig {...configProps} onTest={() => testService("ntfy", settingsApi.testNtfy, setTestingNtfy)} testing={testingNtfy} />}
          {notificationSubTab === "gotify" && <GotifyConfig {...configProps} onTest={() => testService("Gotify", settingsApi.testGotify, setTestingGotify)} testing={testingGotify} />}
          {notificationSubTab === "pushover" && <PushoverConfig {...configProps} onTest={() => testService("Pushover", settingsApi.testPushover, setTestingPushover)} testing={testingPushover} />}
          {notificationSubTab === "slack" && <SlackConfig {...configProps} onTest={() => testService("Slack", settingsApi.testSlack, setTestingSlack)} testing={testingSlack} />}
          {notificationSubTab === "discord" && <DiscordConfig {...configProps} onTest={() => testService("Discord", settingsApi.testDiscord, setTestingDiscord)} testing={testingDiscord} />}
          {notificationSubTab === "telegram" && <TelegramConfig {...configProps} onTest={() => testService("Telegram", settingsApi.testTelegram, setTestingTelegram)} testing={testingTelegram} />}
          {notificationSubTab === "email" && <EmailConfig {...configProps} onTest={() => testService("email", settingsApi.testEmail, setTestingEmail)} testing={testingEmail} />}
        </div>

        <EventNotificationsCard
          settings={notificationSettings}
          onSettingChange={handleBoolChange}
          onTextChange={handleTextChange}
          saving={isSaving}
          hasEnabledService={hasAnyServiceEnabled}
        />
      </div>
    </div>
  );
}
