import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Settings as SettingsIcon, RefreshCw, Bell, Clock, Shield, Database, Info, Lock, Sun, Moon } from "lucide-react";
import { useTheme } from "@/contexts/ThemeContext";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { useSettings, useBulkUpdateSettings, useScanStatus } from "@/hooks/useVulnForge";
import { DatabaseBackupSection } from "@/components/DatabaseBackupSection";
import { ScannerManagementCard } from "@/components/ScannerManagementCard";
import { UserAuthenticationCard } from "@/components/UserAuthenticationCard";
import { ApiKeysCard } from "@/components/ApiKeysCard";
import { HelpTooltip } from "@/components/HelpTooltip";
import { parseSettingInt } from "@/schemas/settings";
import { settingsApi } from "@/lib/api";
import {
  NotificationSubTabs,
  type NotificationSubTab,
  EventNotificationsCard,
  NtfyConfig,
  GotifyConfig,
  PushoverConfig,
  SlackConfig,
  DiscordConfig,
  TelegramConfig,
  EmailConfig,
} from "@/components/notifications";

export function Settings() {
  const navigate = useNavigate();
  const { data: settings, isLoading: settingsLoading } = useSettings();
  const { data: scanStatus } = useScanStatus();
  const bulkUpdateMutation = useBulkUpdateSettings();
  const { theme, setTheme } = useTheme();

  // Active tab state
  const [activeTab, setActiveTab] = useState<"system" | "scanning" | "notifications" | "security" | "data">("system");

  // System Settings
  const [timezonePreset, setTimezonePreset] = useState("UTC");
  const [timezoneCustom, setTimezoneCustom] = useState("");
  const [timezoneMode, setTimezoneMode] = useState<"preset" | "custom">("preset");

  // Scan Settings
  const [scanSchedule, setScanSchedule] = useState("0 2 * * *");
  const [scanTimeout, setScanTimeout] = useState(300);
  const [parallelScans, setParallelScans] = useState(3);
  const [enableSecretScanning, setEnableSecretScanning] = useState(true);
  const [logLevel, setLogLevel] = useState("INFO");

  // Multi-Service Notification Settings
  const [notificationSubTab, setNotificationSubTab] = useState<NotificationSubTab>('ntfy');

  // ntfy settings (existing, keep for backward compatibility)
  const [ntfyEnabled, setNtfyEnabled] = useState(true);
  const [ntfyUrl, setNtfyUrl] = useState("http://ntfy:80");
  const [ntfyTopic, setNtfyTopic] = useState("vulnforge");
  const [ntfyToken, setNtfyToken] = useState("");
  const [notifyOnScanComplete, setNotifyOnScanComplete] = useState(true);
  const [notifyOnCritical, setNotifyOnCritical] = useState(true);
  const [notifyThresholdCritical, setNotifyThresholdCritical] = useState(1);
  const [notifyThresholdHigh, setNotifyThresholdHigh] = useState(10);

  // Gotify settings
  const [gotifyEnabled, setGotifyEnabled] = useState(false);
  const [gotifyServer, setGotifyServer] = useState("");
  const [gotifyToken, setGotifyToken] = useState("");

  // Pushover settings
  const [pushoverEnabled, setPushoverEnabled] = useState(false);
  const [pushoverUserKey, setPushoverUserKey] = useState("");
  const [pushoverApiToken, setPushoverApiToken] = useState("");

  // Slack settings
  const [slackEnabled, setSlackEnabled] = useState(false);
  const [slackWebhookUrl, setSlackWebhookUrl] = useState("");

  // Discord settings
  const [discordEnabled, setDiscordEnabled] = useState(false);
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState("");

  // Telegram settings
  const [telegramEnabled, setTelegramEnabled] = useState(false);
  const [telegramBotToken, setTelegramBotToken] = useState("");
  const [telegramChatId, setTelegramChatId] = useState("");

  // Email settings
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [emailSmtpHost, setEmailSmtpHost] = useState("");
  const [emailSmtpPort, setEmailSmtpPort] = useState("587");
  const [emailSmtpUser, setEmailSmtpUser] = useState("");
  const [emailSmtpPassword, setEmailSmtpPassword] = useState("");
  const [emailSmtpTls, setEmailSmtpTls] = useState(true);
  const [emailFrom, setEmailFrom] = useState("");
  const [emailTo, setEmailTo] = useState("");

  // Event notification settings
  const [notifySecurityEnabled, setNotifySecurityEnabled] = useState(true);
  const [notifySecurityKev, setNotifySecurityKev] = useState(true);
  const [notifySecurityCritical, setNotifySecurityCritical] = useState(true);
  const [notifySecuritySecrets, setNotifySecuritySecrets] = useState(true);
  const [notifyScansEnabled, setNotifyScansEnabled] = useState(true);
  const [notifyScansComplete, setNotifyScansComplete] = useState(true);
  const [notifyScansFailed, setNotifyScansFailed] = useState(true);
  const [notifyScansComplianceComplete, setNotifyScansComplianceComplete] = useState(true);
  const [notifyScansComplianceFailures, setNotifyScansComplianceFailures] = useState(true);
  const [notifySystemEnabled, setNotifySystemEnabled] = useState(false);
  const [notifySystemKevRefresh, setNotifySystemKevRefresh] = useState(false);
  const [notifySystemBackup, setNotifySystemBackup] = useState(false);

  // Notification test states
  const [testingNtfy, setTestingNtfy] = useState(false);
  const [testingGotify, setTestingGotify] = useState(false);
  const [testingPushover, setTestingPushover] = useState(false);
  const [testingSlack, setTestingSlack] = useState(false);
  const [testingDiscord, setTestingDiscord] = useState(false);
  const [testingTelegram, setTestingTelegram] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);

  // Data Retention Settings
  const [keepScanHistoryDays, setKeepScanHistoryDays] = useState(90);

  // UI Preferences
  const [defaultSeverityFilter, setDefaultSeverityFilter] = useState("all");
  const [defaultShowFixableOnly, setDefaultShowFixableOnly] = useState(false);

  // Compliance Settings
  const [complianceScanEnabled, setComplianceScanEnabled] = useState(true);
  const [complianceScanSchedule, setComplianceScanSchedule] = useState("0 3 * * 0");
  const [complianceNotifyOnScan, setComplianceNotifyOnScan] = useState(true);
  const [complianceNotifyOnFailures, setComplianceNotifyOnFailures] = useState(true);

  // KEV Settings
  const [kevCheckingEnabled, setKevCheckingEnabled] = useState(true);
  const [kevCacheHours, setKevCacheHours] = useState(12);
  const [kevLastRefresh, setKevLastRefresh] = useState("");

  // Scanner Offline Resilience Settings
  const [scannerDbMaxAgeHours, setScannerDbMaxAgeHours] = useState(24);
  const [scannerSkipDbUpdateWhenFresh, setScannerSkipDbUpdateWhenFresh] = useState(true);
  const [scannerAllowStaleDb, setScannerAllowStaleDb] = useState(true);
  const [scannerStaleDbWarningHours, setScannerStaleDbWarningHours] = useState(72);

  // API Authentication Settings removed - now managed by ApiKeysCard component
  // User Authentication Settings removed - now managed by UserAuthenticationCard component

  // Auto-save state (status tracked for potential UI indicator, currently unused)
  const [_autoSaveStatus, setAutoSaveStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const hasInitializedRef = useRef(false);
  const lastPayloadRef = useRef<string | null>(null);

  const timezonePresets = ["UTC", "America/New_York", "Europe/London", "Asia/Tokyo"];

  const buildSettingsPayload = (): Record<string, string> => {
    const timezoneValue =
      timezoneMode === "preset"
        ? timezonePreset
        : timezoneCustom.trim() || "UTC";

    return {
      // System settings
      timezone: timezoneValue,
      // Scan settings
      scan_schedule: scanSchedule,
      scan_timeout: scanTimeout.toString(),
      parallel_scans: parallelScans.toString(),
      enable_secret_scanning: enableSecretScanning.toString(),
      log_level: logLevel,
      // Notification settings
      ntfy_enabled: ntfyEnabled.toString(),
      ntfy_url: ntfyUrl,
      ntfy_topic: ntfyTopic,
      ntfy_token: ntfyToken,
      notify_on_scan_complete: notifyOnScanComplete.toString(),
      notify_on_critical: notifyOnCritical.toString(),
      notify_threshold_critical: notifyThresholdCritical.toString(),
      notify_threshold_high: notifyThresholdHigh.toString(),
      // Multi-service notification settings
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
      // Event notification settings
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
      // Data retention
      keep_scan_history_days: keepScanHistoryDays.toString(),
      // UI preferences
      default_severity_filter: defaultSeverityFilter,
      default_show_fixable_only: defaultShowFixableOnly.toString(),
      // Compliance settings
      compliance_scan_enabled: complianceScanEnabled.toString(),
      compliance_scan_schedule: complianceScanSchedule,
      compliance_notify_on_scan: complianceNotifyOnScan.toString(),
      compliance_notify_on_failures: complianceNotifyOnFailures.toString(),
      // KEV settings
      kev_checking_enabled: kevCheckingEnabled.toString(),
      kev_cache_hours: kevCacheHours.toString(),
      // Scanner offline resilience settings
      scanner_db_max_age_hours: scannerDbMaxAgeHours.toString(),
      scanner_skip_db_update_when_fresh: scannerSkipDbUpdateWhenFresh.toString(),
      scanner_allow_stale_db: scannerAllowStaleDb.toString(),
      scanner_stale_db_warning_hours: scannerStaleDbWarningHours.toString(),
      // API Authentication settings removed - now managed by ApiKeysCard component
      // User Authentication settings removed - now managed by UserAuthenticationCard component
    };
  };

  // Load settings from backend when available
  useEffect(() => {
    if (settings) {
      // Convert settings array to object for easier access
      const settingsMap: Record<string, string> = {};
      settings.forEach((s) => {
        settingsMap[s.key] = s.value;
      });

      // System settings
      const tz = settingsMap.timezone || "UTC";
      if (timezonePresets.includes(tz)) {
        setTimezoneMode("preset");
        setTimezonePreset(tz);
        setTimezoneCustom("");
      } else {
        setTimezoneMode("custom");
        setTimezoneCustom(tz);
      }

      // Scan settings
      if (settingsMap.scan_schedule) setScanSchedule(settingsMap.scan_schedule);
      if (settingsMap.scan_timeout) setScanTimeout(parseSettingInt(settingsMap.scan_timeout, 300));
      if (settingsMap.parallel_scans) setParallelScans(parseSettingInt(settingsMap.parallel_scans, 3));
      if (settingsMap.enable_secret_scanning !== undefined)
        setEnableSecretScanning(settingsMap.enable_secret_scanning === "true");
      if (settingsMap.log_level) setLogLevel(settingsMap.log_level);

      // Notification settings
      if (settingsMap.ntfy_enabled !== undefined)
        setNtfyEnabled(settingsMap.ntfy_enabled === "true");
      if (settingsMap.ntfy_url) setNtfyUrl(settingsMap.ntfy_url);
      if (settingsMap.ntfy_topic) setNtfyTopic(settingsMap.ntfy_topic);
      if (settingsMap.ntfy_token) setNtfyToken(settingsMap.ntfy_token);
      if (settingsMap.notify_on_scan_complete !== undefined)
        setNotifyOnScanComplete(settingsMap.notify_on_scan_complete === "true");
      if (settingsMap.notify_on_critical !== undefined)
        setNotifyOnCritical(settingsMap.notify_on_critical === "true");
      if (settingsMap.notify_threshold_critical)
        setNotifyThresholdCritical(parseSettingInt(settingsMap.notify_threshold_critical, 1));
      if (settingsMap.notify_threshold_high)
        setNotifyThresholdHigh(parseSettingInt(settingsMap.notify_threshold_high, 10));

      // Multi-service notification settings
      if (settingsMap.gotify_enabled !== undefined)
        setGotifyEnabled(settingsMap.gotify_enabled === "true");
      if (settingsMap.gotify_server) setGotifyServer(settingsMap.gotify_server);
      if (settingsMap.gotify_token) setGotifyToken(settingsMap.gotify_token);

      if (settingsMap.pushover_enabled !== undefined)
        setPushoverEnabled(settingsMap.pushover_enabled === "true");
      if (settingsMap.pushover_user_key) setPushoverUserKey(settingsMap.pushover_user_key);
      if (settingsMap.pushover_api_token) setPushoverApiToken(settingsMap.pushover_api_token);

      if (settingsMap.slack_enabled !== undefined)
        setSlackEnabled(settingsMap.slack_enabled === "true");
      if (settingsMap.slack_webhook_url) setSlackWebhookUrl(settingsMap.slack_webhook_url);

      if (settingsMap.discord_enabled !== undefined)
        setDiscordEnabled(settingsMap.discord_enabled === "true");
      if (settingsMap.discord_webhook_url) setDiscordWebhookUrl(settingsMap.discord_webhook_url);

      if (settingsMap.telegram_enabled !== undefined)
        setTelegramEnabled(settingsMap.telegram_enabled === "true");
      if (settingsMap.telegram_bot_token) setTelegramBotToken(settingsMap.telegram_bot_token);
      if (settingsMap.telegram_chat_id) setTelegramChatId(settingsMap.telegram_chat_id);

      if (settingsMap.email_enabled !== undefined)
        setEmailEnabled(settingsMap.email_enabled === "true");
      if (settingsMap.email_smtp_host) setEmailSmtpHost(settingsMap.email_smtp_host);
      if (settingsMap.email_smtp_port) setEmailSmtpPort(settingsMap.email_smtp_port);
      if (settingsMap.email_smtp_user) setEmailSmtpUser(settingsMap.email_smtp_user);
      if (settingsMap.email_smtp_password) setEmailSmtpPassword(settingsMap.email_smtp_password);
      if (settingsMap.email_smtp_tls !== undefined)
        setEmailSmtpTls(settingsMap.email_smtp_tls === "true");
      if (settingsMap.email_from) setEmailFrom(settingsMap.email_from);
      if (settingsMap.email_to) setEmailTo(settingsMap.email_to);

      // Event notification settings
      if (settingsMap.notify_security_enabled !== undefined)
        setNotifySecurityEnabled(settingsMap.notify_security_enabled === "true");
      if (settingsMap.notify_security_kev !== undefined)
        setNotifySecurityKev(settingsMap.notify_security_kev === "true");
      if (settingsMap.notify_security_critical !== undefined)
        setNotifySecurityCritical(settingsMap.notify_security_critical === "true");
      if (settingsMap.notify_security_secrets !== undefined)
        setNotifySecuritySecrets(settingsMap.notify_security_secrets === "true");
      if (settingsMap.notify_scans_enabled !== undefined)
        setNotifyScansEnabled(settingsMap.notify_scans_enabled === "true");
      if (settingsMap.notify_scans_complete !== undefined)
        setNotifyScansComplete(settingsMap.notify_scans_complete === "true");
      if (settingsMap.notify_scans_failed !== undefined)
        setNotifyScansFailed(settingsMap.notify_scans_failed === "true");
      if (settingsMap.notify_scans_compliance_complete !== undefined)
        setNotifyScansComplianceComplete(settingsMap.notify_scans_compliance_complete === "true");
      if (settingsMap.notify_scans_compliance_failures !== undefined)
        setNotifyScansComplianceFailures(settingsMap.notify_scans_compliance_failures === "true");
      if (settingsMap.notify_system_enabled !== undefined)
        setNotifySystemEnabled(settingsMap.notify_system_enabled === "true");
      if (settingsMap.notify_system_kev_refresh !== undefined)
        setNotifySystemKevRefresh(settingsMap.notify_system_kev_refresh === "true");
      if (settingsMap.notify_system_backup !== undefined)
        setNotifySystemBackup(settingsMap.notify_system_backup === "true");

      // Data retention
      if (settingsMap.keep_scan_history_days)
        setKeepScanHistoryDays(parseSettingInt(settingsMap.keep_scan_history_days, 90));

      // UI preferences
      if (settingsMap.default_severity_filter)
        setDefaultSeverityFilter(settingsMap.default_severity_filter);
      if (settingsMap.default_show_fixable_only !== undefined)
        setDefaultShowFixableOnly(settingsMap.default_show_fixable_only === "true");

      // Compliance settings
      if (settingsMap.compliance_scan_enabled !== undefined)
        setComplianceScanEnabled(settingsMap.compliance_scan_enabled === "true");
      if (settingsMap.compliance_scan_schedule)
        setComplianceScanSchedule(settingsMap.compliance_scan_schedule);
      if (settingsMap.compliance_notify_on_scan !== undefined)
        setComplianceNotifyOnScan(settingsMap.compliance_notify_on_scan === "true");
      if (settingsMap.compliance_notify_on_failures !== undefined)
        setComplianceNotifyOnFailures(settingsMap.compliance_notify_on_failures === "true");

      // KEV settings
      if (settingsMap.kev_checking_enabled !== undefined)
        setKevCheckingEnabled(settingsMap.kev_checking_enabled === "true");
      if (settingsMap.kev_cache_hours)
        setKevCacheHours(parseSettingInt(settingsMap.kev_cache_hours, 12));
      if (settingsMap.kev_last_refresh)
        setKevLastRefresh(settingsMap.kev_last_refresh);

      // Scanner offline resilience settings
      if (settingsMap.scanner_db_max_age_hours)
        setScannerDbMaxAgeHours(parseSettingInt(settingsMap.scanner_db_max_age_hours, 24));
      if (settingsMap.scanner_skip_db_update_when_fresh !== undefined)
        setScannerSkipDbUpdateWhenFresh(settingsMap.scanner_skip_db_update_when_fresh === "true");
      if (settingsMap.scanner_allow_stale_db !== undefined)
        setScannerAllowStaleDb(settingsMap.scanner_allow_stale_db === "true");
      if (settingsMap.scanner_stale_db_warning_hours)
        setScannerStaleDbWarningHours(parseSettingInt(settingsMap.scanner_stale_db_warning_hours, 72));

      // API Authentication settings loading removed - now managed by ApiKeysCard component
      // User Authentication settings loading removed - now managed by UserAuthenticationCard component

      // Set initial payload to prevent auto-save on first load
      // IMPORTANT: Set both hasInitializedRef and lastPayloadRef together to prevent race condition
      // Use a small delay to ensure all state updates have completed
      setTimeout(() => {
        const initialPayload = buildSettingsPayload();
        lastPayloadRef.current = JSON.stringify(initialPayload);
        hasInitializedRef.current = true;
      }, 100);
    }
  }, [settings]); // eslint-disable-line react-hooks/exhaustive-deps -- Only run when settings load

  // Auto-save settings whenever they change (debounced)
  useEffect(() => {
    if (!settings || !hasInitializedRef.current) {
      return;
    }

    const timer = window.setTimeout(() => {
      const updatedSettings = buildSettingsPayload();
      const serialized = JSON.stringify(updatedSettings);

      if (lastPayloadRef.current === serialized) {
        return;
      }

      lastPayloadRef.current = serialized;
      setAutoSaveStatus("saving");

      bulkUpdateMutation.mutate(updatedSettings, {
        onSuccess: () => {
          setAutoSaveStatus("saved");
          toast.success("Settings saved");
        },
        onError: (error) => {
          console.error("Settings auto-save error:", error);
          setAutoSaveStatus("error");
          handleApiError(error, "Failed to save settings");
        },
      });
    }, 800);

    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    settings,
    timezonePreset,
    timezoneCustom,
    timezoneMode,
    scanSchedule,
    scanTimeout,
    parallelScans,
    enableSecretScanning,
    logLevel,
    ntfyEnabled,
    ntfyUrl,
    ntfyTopic,
    ntfyToken,
    notifyOnScanComplete,
    notifyOnCritical,
    notifyThresholdCritical,
    notifyThresholdHigh,
    keepScanHistoryDays,
    defaultSeverityFilter,
    defaultShowFixableOnly,
    complianceScanEnabled,
    complianceScanSchedule,
    complianceNotifyOnScan,
    complianceNotifyOnFailures,
    kevCheckingEnabled,
    kevCacheHours,
    scannerDbMaxAgeHours,
    scannerSkipDbUpdateWhenFresh,
    scannerAllowStaleDb,
    scannerStaleDbWarningHours,
    // API authentication settings removed - now managed by ApiKeysCard component
    // Multi-service notification settings
    gotifyEnabled,
    gotifyServer,
    gotifyToken,
    pushoverEnabled,
    pushoverUserKey,
    pushoverApiToken,
    slackEnabled,
    slackWebhookUrl,
    discordEnabled,
    discordWebhookUrl,
    telegramEnabled,
    telegramBotToken,
    telegramChatId,
    emailEnabled,
    emailSmtpHost,
    emailSmtpPort,
    emailSmtpUser,
    emailSmtpPassword,
    emailSmtpTls,
    emailFrom,
    emailTo,
    // Event notification settings
    notifySecurityEnabled,
    notifySecurityKev,
    notifySecurityCritical,
    notifySecuritySecrets,
    notifyScansEnabled,
    notifyScansComplete,
    notifyScansFailed,
    notifyScansComplianceComplete,
    notifyScansComplianceFailures,
    notifySystemEnabled,
    notifySystemKevRefresh,
    notifySystemBackup,
    // User authentication settings removed - now managed by UserAuthenticationCard component
  ]);


  // Multi-service notification test handlers
  const handleTestNtfy = async () => {
    setTestingNtfy(true);
    try {
      const result = await settingsApi.testNtfy();
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      handleApiError(error, "Failed to test ntfy connection");
    } finally {
      setTestingNtfy(false);
    }
  };

  const handleTestGotify = async () => {
    setTestingGotify(true);
    try {
      const result = await settingsApi.testGotify();
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      handleApiError(error, "Failed to test Gotify connection");
    } finally {
      setTestingGotify(false);
    }
  };

  const handleTestPushover = async () => {
    setTestingPushover(true);
    try {
      const result = await settingsApi.testPushover();
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      handleApiError(error, "Failed to test Pushover connection");
    } finally {
      setTestingPushover(false);
    }
  };

  const handleTestSlack = async () => {
    setTestingSlack(true);
    try {
      const result = await settingsApi.testSlack();
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      handleApiError(error, "Failed to test Slack connection");
    } finally {
      setTestingSlack(false);
    }
  };

  const handleTestDiscord = async () => {
    setTestingDiscord(true);
    try {
      const result = await settingsApi.testDiscord();
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      handleApiError(error, "Failed to test Discord connection");
    } finally {
      setTestingDiscord(false);
    }
  };

  const handleTestTelegram = async () => {
    setTestingTelegram(true);
    try {
      const result = await settingsApi.testTelegram();
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      handleApiError(error, "Failed to test Telegram connection");
    } finally {
      setTestingTelegram(false);
    }
  };

  const handleTestEmail = async () => {
    setTestingEmail(true);
    try {
      const result = await settingsApi.testEmail();
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      handleApiError(error, "Failed to test email connection");
    } finally {
      setTestingEmail(false);
    }
  };

  // Settings map for notification components
  const notificationSettings: Record<string, unknown> = {
    // ntfy
    ntfy_enabled: ntfyEnabled,
    ntfy_server: ntfyUrl,
    ntfy_topic: ntfyTopic,
    ntfy_token: ntfyToken,
    // gotify
    gotify_enabled: gotifyEnabled,
    gotify_server: gotifyServer,
    gotify_token: gotifyToken,
    // pushover
    pushover_enabled: pushoverEnabled,
    pushover_user_key: pushoverUserKey,
    pushover_api_token: pushoverApiToken,
    // slack
    slack_enabled: slackEnabled,
    slack_webhook_url: slackWebhookUrl,
    // discord
    discord_enabled: discordEnabled,
    discord_webhook_url: discordWebhookUrl,
    // telegram
    telegram_enabled: telegramEnabled,
    telegram_bot_token: telegramBotToken,
    telegram_chat_id: telegramChatId,
    // email
    email_enabled: emailEnabled,
    email_smtp_host: emailSmtpHost,
    email_smtp_port: emailSmtpPort,
    email_smtp_user: emailSmtpUser,
    email_smtp_password: emailSmtpPassword,
    email_smtp_tls: emailSmtpTls,
    email_from: emailFrom,
    email_to: emailTo,
    // event settings
    notify_security_enabled: notifySecurityEnabled,
    notify_security_kev: notifySecurityKev,
    notify_security_critical: notifySecurityCritical,
    notify_security_secrets: notifySecuritySecrets,
    notify_scans_enabled: notifyScansEnabled,
    notify_scans_complete: notifyScansComplete,
    notify_scans_failed: notifyScansFailed,
    notify_scans_compliance_complete: notifyScansComplianceComplete,
    notify_scans_compliance_failures: notifyScansComplianceFailures,
    notify_system_enabled: notifySystemEnabled,
    notify_system_kev_refresh: notifySystemKevRefresh,
    notify_system_backup: notifySystemBackup,
  };

  const handleNotificationSettingChange = (key: string, value: boolean) => {
    switch (key) {
      // ntfy
      case 'ntfy_enabled': setNtfyEnabled(value); break;
      // gotify
      case 'gotify_enabled': setGotifyEnabled(value); break;
      // pushover
      case 'pushover_enabled': setPushoverEnabled(value); break;
      // slack
      case 'slack_enabled': setSlackEnabled(value); break;
      // discord
      case 'discord_enabled': setDiscordEnabled(value); break;
      // telegram
      case 'telegram_enabled': setTelegramEnabled(value); break;
      // email
      case 'email_enabled': setEmailEnabled(value); break;
      case 'email_smtp_tls': setEmailSmtpTls(value); break;
      // event settings
      case 'notify_security_enabled': setNotifySecurityEnabled(value); break;
      case 'notify_security_kev': setNotifySecurityKev(value); break;
      case 'notify_security_critical': setNotifySecurityCritical(value); break;
      case 'notify_security_secrets': setNotifySecuritySecrets(value); break;
      case 'notify_scans_enabled': setNotifyScansEnabled(value); break;
      case 'notify_scans_complete': setNotifyScansComplete(value); break;
      case 'notify_scans_failed': setNotifyScansFailed(value); break;
      case 'notify_scans_compliance_complete': setNotifyScansComplianceComplete(value); break;
      case 'notify_scans_compliance_failures': setNotifyScansComplianceFailures(value); break;
      case 'notify_system_enabled': setNotifySystemEnabled(value); break;
      case 'notify_system_kev_refresh': setNotifySystemKevRefresh(value); break;
      case 'notify_system_backup': setNotifySystemBackup(value); break;
    }
  };

  const handleNotificationTextChange = (key: string, value: string) => {
    switch (key) {
      // ntfy
      case 'ntfy_server': setNtfyUrl(value); break;
      case 'ntfy_topic': setNtfyTopic(value); break;
      case 'ntfy_token': setNtfyToken(value); break;
      // gotify
      case 'gotify_server': setGotifyServer(value); break;
      case 'gotify_token': setGotifyToken(value); break;
      // pushover
      case 'pushover_user_key': setPushoverUserKey(value); break;
      case 'pushover_api_token': setPushoverApiToken(value); break;
      // slack
      case 'slack_webhook_url': setSlackWebhookUrl(value); break;
      // discord
      case 'discord_webhook_url': setDiscordWebhookUrl(value); break;
      // telegram
      case 'telegram_bot_token': setTelegramBotToken(value); break;
      case 'telegram_chat_id': setTelegramChatId(value); break;
      // email
      case 'email_smtp_host': setEmailSmtpHost(value); break;
      case 'email_smtp_port': setEmailSmtpPort(value); break;
      case 'email_smtp_user': setEmailSmtpUser(value); break;
      case 'email_smtp_password': setEmailSmtpPassword(value); break;
      case 'email_from': setEmailFrom(value); break;
      case 'email_to': setEmailTo(value); break;
    }
  };

  const hasAnyServiceEnabled = ntfyEnabled || gotifyEnabled || pushoverEnabled ||
    slackEnabled || discordEnabled || telegramEnabled || emailEnabled;

  if (settingsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <RefreshCw className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-vuln-text">Settings</h1>
          <p className="text-sm text-vuln-text-muted mt-0.5">Configure VulnForge scanning and notifications</p>
        </div>
        <button
          onClick={() => navigate("/about")}
          className="px-3 py-2 bg-vuln-surface-light hover:bg-vuln-border text-vuln-text rounded-lg flex items-center gap-2 text-sm transition-colors"
        >
          <Info className="w-4 h-4" />
          About
        </button>
      </div>

      {/* Tabs */}
      <div className="mb-4 border-b border-vuln-border">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab("system")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "system"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-vuln-text-muted hover:text-vuln-text"
            }`}
          >
            <SettingsIcon className="w-4 h-4 inline-block mr-2" />
            System
          </button>
          <button
            onClick={() => setActiveTab("scanning")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "scanning"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-vuln-text-muted hover:text-vuln-text"
            }`}
          >
            <Shield className="w-4 h-4 inline-block mr-2" />
            Scanning
          </button>
          <button
            onClick={() => setActiveTab("notifications")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "notifications"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-vuln-text-muted hover:text-vuln-text"
            }`}
          >
            <Bell className="w-4 h-4 inline-block mr-2" />
            Notifications
          </button>
          <button
            onClick={() => setActiveTab("security")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "security"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-vuln-text-muted hover:text-vuln-text"
            }`}
          >
            <Lock className="w-4 h-4 inline-block mr-2" />
            Security
          </button>
          <button
            onClick={() => setActiveTab("data")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "data"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-vuln-text-muted hover:text-vuln-text"
            }`}
          >
            <Database className="w-4 h-4 inline-block mr-2" />
            Data & Maintenance
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === "system" && (
        <>
          <div className="columns-1 md:columns-2 gap-4 space-y-4">
            {/* Theme Toggle */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  {theme === "light" ? (
                    <Sun className="w-6 h-6 text-yellow-500" />
                  ) : (
                    <Moon className="w-6 h-6 text-blue-400" />
                  )}
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">Appearance</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Choose your preferred color theme.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="Switch between light and dark color themes. Your preference is saved locally and synced across devices." />
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => setTheme("light")}
                  className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-colors ${
                    theme === "light"
                      ? "bg-blue-600 border-blue-600 text-white"
                      : "bg-vuln-surface-light border-vuln-border text-vuln-text hover:border-blue-500"
                  }`}
                >
                  <Sun className="w-5 h-5" />
                  Light
                </button>
                <button
                  onClick={() => setTheme("dark")}
                  className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-colors ${
                    theme === "dark"
                      ? "bg-blue-600 border-blue-600 text-white"
                      : "bg-vuln-surface-light border-vuln-border text-vuln-text hover:border-blue-500"
                  }`}
                >
                  <Moon className="w-5 h-5" />
                  Dark
                </button>
              </div>
            </div>

            {/* Timezone */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Clock className="w-6 h-6 text-blue-500" />
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">System Timezone</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Controls how schedules and timestamps are interpreted.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="Set the timezone for all timestamps and scheduled scans. Uses IANA timezone format (e.g., America/Chicago). All dates in the UI will display in this timezone." />
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Timezone
                  </label>
                  <select
                    value={timezoneMode === "preset" ? timezonePreset : "custom"}
                    onChange={(e) => {
                      const value = e.target.value;
                      if (value === "custom") {
                        setTimezoneMode("custom");
                      } else {
                        setTimezoneMode("preset");
                        setTimezonePreset(value);
                      }
                    }}
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="UTC">UTC (default)</option>
                    <option value="America/New_York">America/New_York</option>
                    <option value="America/Chicago">America/Chicago</option>
                    <option value="America/Denver">America/Denver</option>
                    <option value="America/Los_Angeles">America/Los_Angeles</option>
                    <option value="Europe/London">Europe/London</option>
                    <option value="Europe/Paris">Europe/Paris</option>
                    <option value="Asia/Tokyo">Asia/Tokyo</option>
                    <option value="Asia/Shanghai">Asia/Shanghai</option>
                    <option value="Australia/Sydney">Australia/Sydney</option>
                    <option value="custom">Custom…</option>
                  </select>
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Uses IANA timezone names (e.g., UTC, America/Los_Angeles).
                  </p>
                </div>

                {timezoneMode === "custom" && (
                  <div>
                    <label className="block text-sm font-medium text-vuln-text mb-2">
                      Custom IANA Timezone
                    </label>
                    <input
                      type="text"
                      value={timezoneCustom}
                      onChange={(e) => setTimezoneCustom(e.target.value)}
                      placeholder="e.g., America/Phoenix"
                      className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                )}
              </div>
            </div>

            {/* Log Level */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <SettingsIcon className="w-6 h-6 text-orange-500" />
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">Log Level</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Configure application logging verbosity.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="Control how much detail is written to logs. DEBUG shows everything, ERROR shows only critical issues. Use DEBUG for troubleshooting, INFO for normal operation." />
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Log Level
                  </label>
                  <select
                    value={logLevel}
                    onChange={(e) => setLogLevel(e.target.value)}
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="DEBUG">DEBUG</option>
                    <option value="INFO">INFO</option>
                    <option value="WARNING">WARNING</option>
                    <option value="ERROR">ERROR</option>
                  </select>
                  <p className="text-xs text-vuln-text-disabled mt-1">Application logging verbosity</p>
                </div>
              </div>
            </div>
          </div>

          {/* Info Box - System tab only */}
          <div className="mt-4 bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <Clock className="w-5 h-5 text-blue-500 mt-0.5" />
              <div>
                <h3 className="text-sm font-medium text-blue-500 mb-1">Persistent Settings</h3>
                <p className="text-sm text-vuln-text-muted">
                  All settings are stored in the database and persist across container restarts. Changes are saved
                  automatically as you edit them.
                </p>
              </div>
            </div>
          </div>
        </>
      )}
      {activeTab === "scanning" && (
        <>
          {/* Scanner Management */}
          <div className="mb-6">
            <ScannerManagementCard />
          </div>

          {/* Scan Settings + Offline Resilience + UI Preferences - masonry layout */}
          <div className="columns-1 md:columns-2 gap-4 space-y-4">
            {/* Scan Settings */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Shield className="w-6 h-6 text-blue-500" />
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">Scan Settings</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Configure scan schedule and performance.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="Configure vulnerability scan behavior: schedule, timeout limits, parallel workers, and secret detection. Performance Note: Values above 35 parallel workers may cause timeout errors and database lock issues. Recommended: 30-35 workers for optimal performance. Restart Required: Changes to parallel workers require a container restart to take effect." />
              </div>

              {scanStatus?.status === "scanning" && (
                <div className="flex items-center gap-2 text-sm mb-4 px-2 py-1.5 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                  <RefreshCw className="w-4 h-4 text-blue-500 animate-spin" />
                  <span className="text-blue-400">
                    Scanning {scanStatus.current_container} ({scanStatus.progress_current}/{scanStatus.progress_total})
                  </span>
                </div>
              )}

              <div className="space-y-4">
                {/* Scan Schedule */}
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Scan Schedule (Cron)
                  </label>
                  <input
                    type="text"
                    value={scanSchedule}
                    onChange={(e) => setScanSchedule(e.target.value)}
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="0 2 * * *"
                  />
                  <p className="text-xs text-vuln-text-disabled mt-1">Current: Daily at 2:00 AM</p>
                </div>

                {/* Scan Timeout */}
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Scan Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    value={scanTimeout}
                    onChange={(e) => setScanTimeout(Number(e.target.value))}
                    min={60}
                    max={600}
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <p className="text-xs text-vuln-text-disabled mt-1">Maximum time per container scan</p>
                </div>

                {/* Parallel Scans */}
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Parallel Scans
                  </label>
                  <input
                    type="number"
                    value={parallelScans}
                    onChange={(e) => setParallelScans(Number(e.target.value))}
                    min={1}
                    max={50}
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <p className="text-xs text-vuln-text-disabled mt-1">Number of containers to scan simultaneously</p>
                </div>

                {/* Secret Scanning Toggle */}
                <div>
                  <label className="flex items-center justify-between cursor-pointer group">
                    <div>
                      <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                        Enable Secret Detection
                      </span>
                      <p className="text-xs text-vuln-text-disabled mt-1">
                        Scan for exposed credentials (API keys, tokens, passwords). Disabling speeds up scans but skips security checks.
                      </p>
                    </div>
                    <div className="relative">
                      <input
                        type="checkbox"
                        checked={enableSecretScanning}
                        onChange={(e) => setEnableSecretScanning(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                    </div>
                  </label>
                </div>
              </div>
            </div>

            {/* Scanner Offline Resilience */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Database className="w-6 h-6 text-blue-500" />
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">Scanner Offline Resilience</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Configure database update behavior.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="Configure how VulnForge handles vulnerability database updates. These settings help VulnForge work better in environments with limited or unreliable internet connectivity. Enable 'Skip Database Updates When Fresh' to reduce network dependency by ~80%." />
              </div>

              <div className="space-y-4">
                {/* Skip DB Update When Fresh */}
                <div>
                  <label className="flex items-center justify-between cursor-pointer group">
                    <div>
                      <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                        Skip Database Updates When Fresh
                      </span>
                      <p className="text-xs text-vuln-text-disabled mt-1">
                        Skip updating scanner databases if they're fresh (saves network bandwidth and scan time)
                      </p>
                    </div>
                    <div className="relative">
                      <input
                        type="checkbox"
                        checked={scannerSkipDbUpdateWhenFresh}
                        onChange={(e) => setScannerSkipDbUpdateWhenFresh(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                    </div>
                  </label>
                </div>

                {/* Max DB Age Hours */}
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Maximum Database Age (Hours)
                  </label>
                  <input
                    type="number"
                    value={scannerDbMaxAgeHours}
                    onChange={(e) => setScannerDbMaxAgeHours(parseSettingInt(e.target.value, 24))}
                    min="1"
                    max="168"
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Maximum age for scanner databases to be considered "fresh" (default: 24 hours)
                  </p>
                </div>

                {/* Stale DB Warning Hours */}
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Stale Database Warning (Hours)
                  </label>
                  <input
                    type="number"
                    value={scannerStaleDbWarningHours}
                    onChange={(e) => setScannerStaleDbWarningHours(parseSettingInt(e.target.value, 72))}
                    min="1"
                    max="720"
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Show warnings when scanner databases exceed this age (default: 72 hours)
                  </p>
                </div>

                {/* Allow Stale DB */}
                <div>
                  <label className="flex items-center justify-between cursor-pointer group">
                    <div>
                      <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                        Allow Scans with Stale Databases
                      </span>
                      <p className="text-xs text-vuln-text-disabled mt-1">
                        Allow scanning even when databases are older than the maximum age (useful for offline environments)
                      </p>
                    </div>
                    <div className="relative">
                      <input
                        type="checkbox"
                        checked={scannerAllowStaleDb}
                        onChange={(e) => setScannerAllowStaleDb(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                    </div>
                  </label>
                </div>
              </div>
            </div>

            {/* UI Preferences */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <SettingsIcon className="w-6 h-6 text-orange-500" />
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">UI Preferences</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Customize default view settings.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="Customize how vulnerability data is displayed. Set default filters to focus on the severity levels most relevant to your security priorities." />
              </div>

              <div className="space-y-4">
                {/* Default Severity Filter */}
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Default Severity Filter
                  </label>
                  <select
                    value={defaultSeverityFilter}
                    onChange={(e) => setDefaultSeverityFilter(e.target.value)}
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical Only</option>
                    <option value="high">High & Above</option>
                    <option value="medium">Medium & Above</option>
                    <option value="low">Low & Above</option>
                  </select>
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Default filter when viewing vulnerabilities
                  </p>
                </div>

                {/* Show Fixable Only */}
                <div>
                  <label className="flex items-center justify-between cursor-pointer group">
                    <div>
                      <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                        Show Fixable Only by Default
                      </span>
                      <p className="text-xs text-vuln-text-disabled mt-1">
                        Only show vulnerabilities with available fixes
                      </p>
                    </div>
                    <div className="relative">
                      <input
                        type="checkbox"
                        checked={defaultShowFixableOnly}
                        onChange={(e) => setDefaultShowFixableOnly(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                    </div>
                  </label>
                </div>

              </div>
            </div>
          </div>
        </>
      )}

      {activeTab === "security" && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Left Column */}
            <div className="space-y-4">
              {/* API Keys Card */}
              <ApiKeysCard />

              {/* KEV Settings */}
              <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Shield className="w-6 h-6 text-red-500" />
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">KEV (Known Exploited Vulnerabilities)</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Track actively exploited vulnerabilities from CISA's KEV catalog.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="CISA's Known Exploited Vulnerabilities catalog tracks CVEs actively being exploited in the wild. KEV vulnerabilities are confirmed by CISA to be used in real-world attacks and should be prioritized for immediate remediation. Visit cisa.gov/known-exploited-vulnerabilities-catalog for the full catalog." />
              </div>

              <div className="space-y-4">
                {/* Enable KEV Checking */}
                <div>
                  <label className="flex items-center justify-between cursor-pointer group">
                    <div>
                      <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                        Enable KEV Checking
                      </span>
                      <p className="text-xs text-vuln-text-disabled mt-1">
                        Check CVEs against CISA's Known Exploited Vulnerabilities catalog
                      </p>
                    </div>
                    <div className="relative">
                      <input
                        type="checkbox"
                        checked={kevCheckingEnabled}
                        onChange={(e) => setKevCheckingEnabled(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                    </div>
                  </label>
                </div>

                {/* Cache Hours */}
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Cache Duration (Hours)
                  </label>
                  <input
                    type="number"
                    value={kevCacheHours}
                    onChange={(e) => setKevCacheHours(parseSettingInt(e.target.value, 12))}
                    disabled={!kevCheckingEnabled}
                    min="1"
                    max="72"
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                  />
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    How long to cache the KEV catalog before refreshing
                  </p>
                </div>

                {/* Last Refresh */}
                {kevLastRefresh && (
                  <div className="bg-vuln-surface-light/20 border border-vuln-border rounded-lg p-3">
                    <p className="text-sm text-vuln-text">
                      <strong>Last KEV Refresh:</strong>{" "}
                      <span className="text-vuln-text-muted">
                        {new Date(kevLastRefresh).toLocaleString()}
                      </span>
                    </p>
                  </div>
                )}
              </div>
              </div>
            </div>

            {/* Right Column */}
            <div className="space-y-4">
              {/* User Authentication Card */}
              <UserAuthenticationCard />
            </div>
          </div>
        </>
      )}

      {activeTab === "notifications" && (
        <div className="space-y-6">
          {/* Service Sub-tabs */}
          <NotificationSubTabs
            activeSubTab={notificationSubTab}
            onSubTabChange={setNotificationSubTab}
            enabledServices={{
              ntfy: ntfyEnabled,
              gotify: gotifyEnabled,
              pushover: pushoverEnabled,
              slack: slackEnabled,
              discord: discordEnabled,
              telegram: telegramEnabled,
              email: emailEnabled,
            }}
          />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Service Configuration (left column) */}
            <div>
              {notificationSubTab === 'ntfy' && (
                <NtfyConfig
                  settings={notificationSettings}
                  onSettingChange={handleNotificationSettingChange}
                  onTextChange={handleNotificationTextChange}
                  onTest={handleTestNtfy}
                  testing={testingNtfy}
                  saving={bulkUpdateMutation.isPending}
                />
              )}
              {notificationSubTab === 'gotify' && (
                <GotifyConfig
                  settings={notificationSettings}
                  onSettingChange={handleNotificationSettingChange}
                  onTextChange={handleNotificationTextChange}
                  onTest={handleTestGotify}
                  testing={testingGotify}
                  saving={bulkUpdateMutation.isPending}
                />
              )}
              {notificationSubTab === 'pushover' && (
                <PushoverConfig
                  settings={notificationSettings}
                  onSettingChange={handleNotificationSettingChange}
                  onTextChange={handleNotificationTextChange}
                  onTest={handleTestPushover}
                  testing={testingPushover}
                  saving={bulkUpdateMutation.isPending}
                />
              )}
              {notificationSubTab === 'slack' && (
                <SlackConfig
                  settings={notificationSettings}
                  onSettingChange={handleNotificationSettingChange}
                  onTextChange={handleNotificationTextChange}
                  onTest={handleTestSlack}
                  testing={testingSlack}
                  saving={bulkUpdateMutation.isPending}
                />
              )}
              {notificationSubTab === 'discord' && (
                <DiscordConfig
                  settings={notificationSettings}
                  onSettingChange={handleNotificationSettingChange}
                  onTextChange={handleNotificationTextChange}
                  onTest={handleTestDiscord}
                  testing={testingDiscord}
                  saving={bulkUpdateMutation.isPending}
                />
              )}
              {notificationSubTab === 'telegram' && (
                <TelegramConfig
                  settings={notificationSettings}
                  onSettingChange={handleNotificationSettingChange}
                  onTextChange={handleNotificationTextChange}
                  onTest={handleTestTelegram}
                  testing={testingTelegram}
                  saving={bulkUpdateMutation.isPending}
                />
              )}
              {notificationSubTab === 'email' && (
                <EmailConfig
                  settings={notificationSettings}
                  onSettingChange={handleNotificationSettingChange}
                  onTextChange={handleNotificationTextChange}
                  onTest={handleTestEmail}
                  testing={testingEmail}
                  saving={bulkUpdateMutation.isPending}
                />
              )}
            </div>

            {/* Event Notifications (right column) */}
            <EventNotificationsCard
              settings={notificationSettings}
              onSettingChange={handleNotificationSettingChange}
              onTextChange={handleNotificationTextChange}
              saving={bulkUpdateMutation.isPending}
              hasEnabledService={hasAnyServiceEnabled}
            />
          </div>
        </div>
      )}


      {activeTab === "data" && (
        <>
          <div className="columns-1 md:columns-2 gap-4 space-y-4">
            {/* Database Backup */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Database className="w-6 h-6 text-purple-500" />
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">Database Backup</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Backup and restore your VulnForge database.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="Create and restore database backups. Backups include all containers, scan history, vulnerabilities, and settings. Download backups for disaster recovery or migrate to another instance." />
              </div>

              <div className="space-y-4">
                <DatabaseBackupSection />
              </div>
            </div>

            {/* Data Retention */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Clock className="w-6 h-6 text-blue-500" />
                  <div>
                    <h2 className="text-xl font-semibold text-vuln-text">Data Retention</h2>
                    <p className="text-sm text-vuln-text-muted mt-0.5">
                      Configure how long scan history is kept in the database.
                    </p>
                  </div>
                </div>
                <HelpTooltip content="Control how long historical scan data is retained. Older scans are automatically purged to save disk space. The most recent scan for each container is always kept. Data Retention Policy: Old scan history is cleaned up automatically. Current container states and the latest scan results are always retained regardless of this setting." />
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-2">
                    Keep Scan History (Days)
                  </label>
                  <input
                    type="number"
                    value={keepScanHistoryDays}
                    onChange={(e) => setKeepScanHistoryDays(parseSettingInt(e.target.value, 90))}
                    min="1"
                    max="365"
                    className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Scan results older than this will be automatically deleted
                  </p>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
