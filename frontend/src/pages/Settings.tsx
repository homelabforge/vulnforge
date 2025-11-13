import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Settings as SettingsIcon, Save, RefreshCw, Bell, Clock, Shield, Database, Eye, EyeOff, Info, FileCheck, Lock, AlertCircle, Key, Users } from "lucide-react";
import { toast } from "sonner";
import { useSettings, useBulkUpdateSettings, useScanStatus } from "@/hooks/useVulnForge";
import { DatabaseBackupSection } from "@/components/DatabaseBackupSection";
import { ScannerManagementCard } from "@/components/ScannerManagementCard";

export function Settings() {
  const navigate = useNavigate();
  const { data: settings, isLoading: settingsLoading } = useSettings();
  const { data: scanStatus } = useScanStatus();
  const bulkUpdateMutation = useBulkUpdateSettings();

  // Active tab state
  const [activeTab, setActiveTab] = useState<"scanning" | "notifications" | "security" | "data">("scanning");

  // Scan Settings
  const [scanSchedule, setScanSchedule] = useState("0 2 * * *");
  const [scanTimeout, setScanTimeout] = useState(300);
  const [parallelScans, setParallelScans] = useState(3);
  const [enableSecretScanning, setEnableSecretScanning] = useState(true);
  const [logLevel, setLogLevel] = useState("INFO");

  // Notification Settings
  const [ntfyEnabled, setNtfyEnabled] = useState(true);
  const [ntfyUrl, setNtfyUrl] = useState("http://ntfy:80");
  const [ntfyTopic, setNtfyTopic] = useState("vulnforge");
  const [ntfyToken, setNtfyToken] = useState("");
  const [showNtfyToken, setShowNtfyToken] = useState(false);
  const [notifyOnScanComplete, setNotifyOnScanComplete] = useState(true);
  const [notifyOnCritical, setNotifyOnCritical] = useState(true);
  const [notifyThresholdCritical, setNotifyThresholdCritical] = useState(1);
  const [notifyThresholdHigh, setNotifyThresholdHigh] = useState(10);

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

  // Authentication Settings
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authProvider, setAuthProvider] = useState("none");
  // Authentik settings
  const [authAuthentikHeaderUsername, setAuthAuthentikHeaderUsername] = useState("X-Authentik-Username");
  const [authAuthentikHeaderEmail, setAuthAuthentikHeaderEmail] = useState("X-Authentik-Email");
  const [authAuthentikHeaderGroups, setAuthAuthentikHeaderGroups] = useState("X-Authentik-Groups");
  // Custom headers settings
  const [authCustomHeaderUsername, setAuthCustomHeaderUsername] = useState("X-Remote-User");
  const [authCustomHeaderEmail, setAuthCustomHeaderEmail] = useState("X-Remote-Email");
  const [authCustomHeaderGroups, setAuthCustomHeaderGroups] = useState("X-Remote-Groups");
  // API keys (JSON array)
  const [authApiKeys, setAuthApiKeys] = useState("[]");
  // Basic auth users (JSON array)
  const [authBasicUsers, setAuthBasicUsers] = useState("[]");
  // Admin configuration
  const [authAdminGroup, setAuthAdminGroup] = useState("vulnforge-admins");
  const [authAdminUsernames, setAuthAdminUsernames] = useState("[]");

  // Load settings from backend when available
  useEffect(() => {
    if (settings) {
      // Convert settings array to object for easier access
      const settingsMap: Record<string, string> = {};
      settings.forEach((s) => {
        settingsMap[s.key] = s.value;
      });

      // Scan settings
      if (settingsMap.scan_schedule) setScanSchedule(settingsMap.scan_schedule);
      if (settingsMap.scan_timeout) setScanTimeout(parseInt(settingsMap.scan_timeout));
      if (settingsMap.parallel_scans) setParallelScans(parseInt(settingsMap.parallel_scans));
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
        setNotifyThresholdCritical(parseInt(settingsMap.notify_threshold_critical));
      if (settingsMap.notify_threshold_high)
        setNotifyThresholdHigh(parseInt(settingsMap.notify_threshold_high));

      // Data retention
      if (settingsMap.keep_scan_history_days)
        setKeepScanHistoryDays(parseInt(settingsMap.keep_scan_history_days));

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
        setKevCacheHours(parseInt(settingsMap.kev_cache_hours));
      if (settingsMap.kev_last_refresh)
        setKevLastRefresh(settingsMap.kev_last_refresh);

      // Scanner offline resilience settings
      if (settingsMap.scanner_db_max_age_hours)
        setScannerDbMaxAgeHours(parseInt(settingsMap.scanner_db_max_age_hours));
      if (settingsMap.scanner_skip_db_update_when_fresh !== undefined)
        setScannerSkipDbUpdateWhenFresh(settingsMap.scanner_skip_db_update_when_fresh === "true");
      if (settingsMap.scanner_allow_stale_db !== undefined)
        setScannerAllowStaleDb(settingsMap.scanner_allow_stale_db === "true");
      if (settingsMap.scanner_stale_db_warning_hours)
        setScannerStaleDbWarningHours(parseInt(settingsMap.scanner_stale_db_warning_hours));

      // Authentication settings
      if (settingsMap.auth_enabled !== undefined)
        setAuthEnabled(settingsMap.auth_enabled === "true");
      if (settingsMap.auth_provider) setAuthProvider(settingsMap.auth_provider);
      if (settingsMap.auth_authentik_header_username)
        setAuthAuthentikHeaderUsername(settingsMap.auth_authentik_header_username);
      if (settingsMap.auth_authentik_header_email)
        setAuthAuthentikHeaderEmail(settingsMap.auth_authentik_header_email);
      if (settingsMap.auth_authentik_header_groups)
        setAuthAuthentikHeaderGroups(settingsMap.auth_authentik_header_groups);
      if (settingsMap.auth_custom_header_username)
        setAuthCustomHeaderUsername(settingsMap.auth_custom_header_username);
      if (settingsMap.auth_custom_header_email)
        setAuthCustomHeaderEmail(settingsMap.auth_custom_header_email);
      if (settingsMap.auth_custom_header_groups)
        setAuthCustomHeaderGroups(settingsMap.auth_custom_header_groups);
      if (settingsMap.auth_api_keys) setAuthApiKeys(settingsMap.auth_api_keys);
      if (settingsMap.auth_basic_users) setAuthBasicUsers(settingsMap.auth_basic_users);
      if (settingsMap.auth_admin_group) setAuthAdminGroup(settingsMap.auth_admin_group);
      if (settingsMap.auth_admin_usernames) setAuthAdminUsernames(settingsMap.auth_admin_usernames);
    }
  }, [settings]);

  const handleSave = async () => {
    try {
      // Build settings object for bulk update
      const updatedSettings: Record<string, string> = {
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
        // Authentication settings
        auth_enabled: authEnabled.toString(),
        auth_provider: authProvider,
        auth_authentik_header_username: authAuthentikHeaderUsername,
        auth_authentik_header_email: authAuthentikHeaderEmail,
        auth_authentik_header_groups: authAuthentikHeaderGroups,
        auth_custom_header_username: authCustomHeaderUsername,
        auth_custom_header_email: authCustomHeaderEmail,
        auth_custom_header_groups: authCustomHeaderGroups,
        auth_api_keys: authApiKeys,
        auth_basic_users: authBasicUsers,
        auth_admin_group: authAdminGroup,
        auth_admin_usernames: authAdminUsernames,
      };

      await bulkUpdateMutation.mutateAsync(updatedSettings);
      toast.success("Settings saved successfully");
    } catch (error) {
      toast.error("Failed to save settings");
      console.error("Settings save error:", error);
    }
  };

  const handleTestNotification = async () => {
    try {
      // Send a test notification via the backend API
      const response = await fetch("/api/v1/notifications/test", {
        method: "POST",
      });

      if (response.ok) {
        toast.success("Test notification sent successfully!");
      } else {
        const error = await response.json();
        toast.error(`Failed to send test notification: ${error.detail || "Unknown error"}`);
      }
    } catch (error) {
      toast.error("Failed to send test notification");
      console.error("Test notification error:", error);
    }
  };

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
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Settings</h1>
          <p className="text-gray-400 mt-1">Configure VulnForge scanning and notifications</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => navigate("/about")}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg flex items-center gap-2 transition-colors"
          >
            <Info className="w-4 h-4" />
            About
          </button>
          <button
            onClick={handleSave}
            disabled={bulkUpdateMutation.isPending}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            {bulkUpdateMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            Save Settings
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6 border-b border-gray-700">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab("scanning")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "scanning"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-gray-400 hover:text-gray-300"
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
                : "text-gray-400 hover:text-gray-300"
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
                : "text-gray-400 hover:text-gray-300"
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
                : "text-gray-400 hover:text-gray-300"
            }`}
          >
            <Database className="w-4 h-4 inline-block mr-2" />
            Data & Maintenance
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === "scanning" && (
        <>
          {/* Scanner Management */}
          <div className="mb-6">
            <ScannerManagementCard />
          </div>
        </>
      )}

      {activeTab === "security" && (
        <>
          {/* Authentication Settings */}
      <div className="mb-6 bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
        <div className="flex items-center gap-3 mb-4">
          <Lock className="w-6 h-6 text-purple-500" />
          <div>
            <h2 className="text-xl font-semibold text-white">Authentication</h2>
            <p className="text-sm text-gray-400 mt-0.5">Configure access control and authentication providers</p>
          </div>
        </div>

        {/* Production Warning Banner - shown when auth is disabled */}
        {!authEnabled && (
          <div className="mb-6 p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-amber-400">Authentication Disabled</p>
              <p className="text-xs text-amber-300/70 mt-1">
                VulnForge is currently accessible without authentication. Enable authentication for production deployments to secure access to vulnerability data and administrative functions.
              </p>
            </div>
          </div>
        )}

        {/* Master Toggle */}
        <div className="mb-6">
          <label className="flex items-center justify-between cursor-pointer group">
            <div>
              <span className="text-sm font-medium text-gray-300 group-hover:text-white transition-colors">
                Enable Authentication
              </span>
              <p className="text-xs text-gray-500 mt-1">
                Require users to authenticate before accessing VulnForge
              </p>
            </div>
            <div className="relative">
              <input
                type="checkbox"
                checked={authEnabled}
                onChange={(e) => setAuthEnabled(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
            </div>
          </label>
        </div>

        {/* Provider Selection */}
        {authEnabled && (
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Authentication Provider
              </label>
              <select
                value={authProvider}
                onChange={(e) => setAuthProvider(e.target.value)}
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
              >
                <option value="none">None (Disable)</option>
                <option value="authentik">Authentik (Forward Auth)</option>
                <option value="custom_headers">Custom Headers (Authelia/nginx)</option>
                <option value="api_key">API Keys</option>
                <option value="basic_auth">Basic Authentication</option>
              </select>
              <p className="text-xs text-gray-500 mt-1">
                Select how users will authenticate to VulnForge
              </p>
            </div>

            {/* Authentik Provider Settings */}
            {authProvider === "authentik" && (
              <div className="p-4 bg-[#0f1419] border border-gray-700 rounded-lg space-y-4">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="w-4 h-4 text-purple-400" />
                  <h3 className="text-sm font-semibold text-white">Authentik Configuration</h3>
                </div>
                <p className="text-xs text-gray-500 mb-4">
                  Configure HTTP headers sent by Authentik forward auth proxy
                </p>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">Username Header</label>
                  <input
                    type="text"
                    value={authAuthentikHeaderUsername}
                    onChange={(e) => setAuthAuthentikHeaderUsername(e.target.value)}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-gray-700 rounded text-sm text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">Email Header</label>
                  <input
                    type="text"
                    value={authAuthentikHeaderEmail}
                    onChange={(e) => setAuthAuthentikHeaderEmail(e.target.value)}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-gray-700 rounded text-sm text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">Groups Header</label>
                  <input
                    type="text"
                    value={authAuthentikHeaderGroups}
                    onChange={(e) => setAuthAuthentikHeaderGroups(e.target.value)}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-gray-700 rounded text-sm text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  />
                </div>
              </div>
            )}

            {/* Custom Headers Provider Settings */}
            {authProvider === "custom_headers" && (
              <div className="p-4 bg-[#0f1419] border border-gray-700 rounded-lg space-y-4">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="w-4 h-4 text-purple-400" />
                  <h3 className="text-sm font-semibold text-white">Custom Headers Configuration</h3>
                </div>
                <p className="text-xs text-gray-500 mb-4">
                  Configure HTTP headers sent by your reverse proxy (Authelia, nginx, etc.)
                </p>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">Username Header</label>
                  <input
                    type="text"
                    value={authCustomHeaderUsername}
                    onChange={(e) => setAuthCustomHeaderUsername(e.target.value)}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-gray-700 rounded text-sm text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">Email Header</label>
                  <input
                    type="text"
                    value={authCustomHeaderEmail}
                    onChange={(e) => setAuthCustomHeaderEmail(e.target.value)}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-gray-700 rounded text-sm text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">Groups Header</label>
                  <input
                    type="text"
                    value={authCustomHeaderGroups}
                    onChange={(e) => setAuthCustomHeaderGroups(e.target.value)}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-gray-700 rounded text-sm text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  />
                </div>
              </div>
            )}

            {/* API Keys Provider Settings */}
            {authProvider === "api_key" && (
              <div className="p-4 bg-[#0f1419] border border-gray-700 rounded-lg">
                <div className="flex items-center gap-2 mb-3">
                  <Key className="w-4 h-4 text-purple-400" />
                  <h3 className="text-sm font-semibold text-white">API Keys Configuration</h3>
                </div>
                <p className="text-xs text-gray-500 mb-4">
                  Manage API keys for programmatic access. Format: JSON array
                </p>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">
                    API Keys (JSON)
                  </label>
                  <textarea
                    value={authApiKeys}
                    onChange={(e) => setAuthApiKeys(e.target.value)}
                    rows={4}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-gray-700 rounded text-xs font-mono text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                    placeholder='[{"key": "abc123...", "name": "my-script", "admin": true}]'
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Example: {`[{"key": "secret_key_here", "name": "automation-script", "admin": false}]`}
                  </p>
                </div>
              </div>
            )}

            {/* Basic Auth Provider Settings */}
            {authProvider === "basic_auth" && (
              <div className="p-4 bg-[#0f1419] border border-gray-700 rounded-lg">
                <div className="flex items-center gap-2 mb-3">
                  <Users className="w-4 h-4 text-purple-400" />
                  <h3 className="text-sm font-semibold text-white">Basic Authentication Configuration</h3>
                </div>
                <p className="text-xs text-gray-500 mb-4">
                  Manage users with bcrypt-hashed passwords. Format: JSON array
                </p>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">
                    Users (JSON)
                  </label>
                  <textarea
                    value={authBasicUsers}
                    onChange={(e) => setAuthBasicUsers(e.target.value)}
                    rows={4}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-gray-700 rounded text-xs font-mono text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                    placeholder='[{"username": "admin", "password_hash": "$2b$12$...", "admin": true}]'
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Password hashes must be bcrypt format. Use a tool like <code className="text-purple-400">htpasswd -bnBC 12 "" password</code>
                  </p>
                </div>
              </div>
            )}

            {/* Admin Configuration - shown for all providers except none */}
            {authProvider !== "none" && (
              <div className="p-4 bg-blue-900/10 border border-blue-500/20 rounded-lg space-y-4">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="w-4 h-4 text-blue-400" />
                  <h3 className="text-sm font-semibold text-white">Admin Configuration</h3>
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">
                    Admin Group Name
                  </label>
                  <input
                    type="text"
                    value={authAdminGroup}
                    onChange={(e) => setAuthAdminGroup(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Users in this group will have admin privileges (for header-based auth)
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-2">
                    Admin Usernames (JSON array)
                  </label>
                  <textarea
                    value={authAdminUsernames}
                    onChange={(e) => setAuthAdminUsernames(e.target.value)}
                    rows={2}
                    className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded text-xs font-mono text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder='["admin", "john@example.com"]'
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Fallback admin list when group-based admin detection is unavailable
                  </p>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Help Text */}
        <div className="mt-6 p-4 bg-purple-900/10 border border-purple-500/20 rounded-lg">
          <p className="text-xs text-purple-300/70">
            <strong className="text-purple-400">Authentication Providers:</strong> Choose based on your infrastructure. Authentik/Custom Headers for SSO, API Keys for automation, Basic Auth for simple deployments.
          </p>
          <p className="text-xs text-purple-300/70 mt-2">
            <strong className="text-purple-400">Security Note:</strong> Admin users can access maintenance endpoints (backup/restore, cache clear, KEV refresh). Regular users have read-only access to vulnerability data.
          </p>
        </div>
      </div>
        </>
      )}

      {activeTab === "scanning" && (
        <>
        {/* Scan Settings */}
        <div className="mb-6 bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Shield className="w-6 h-6 text-blue-500" />
              <h2 className="text-xl font-semibold text-white">Scan Settings</h2>
            </div>
            {scanStatus?.status === "scanning" && (
              <div className="flex items-center gap-2 text-sm">
                <RefreshCw className="w-4 h-4 text-blue-500 animate-spin" />
                <span className="text-blue-400">
                  Scanning {scanStatus.current_container} ({scanStatus.progress_current}/{scanStatus.progress_total})
                </span>
              </div>
            )}
          </div>

          <div className="space-y-4">
            {/* Scan Schedule */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Scan Schedule (Cron)
              </label>
              <input
                type="text"
                value={scanSchedule}
                onChange={(e) => setScanSchedule(e.target.value)}
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="0 2 * * *"
              />
              <p className="text-xs text-gray-500 mt-1">Current: Daily at 2:00 AM</p>
            </div>

            {/* Scan Timeout */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Scan Timeout (seconds)
              </label>
              <input
                type="number"
                value={scanTimeout}
                onChange={(e) => setScanTimeout(Number(e.target.value))}
                min={60}
                max={600}
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-500 mt-1">Maximum time per container scan</p>
            </div>

            {/* Parallel Scans */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Parallel Scans
              </label>
              <input
                type="number"
                value={parallelScans}
                onChange={(e) => setParallelScans(Number(e.target.value))}
                min={1}
                max={10}
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-500 mt-1">Number of containers to scan simultaneously</p>
            </div>

            {/* Secret Scanning Toggle */}
            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-gray-300 group-hover:text-white transition-colors">
                    Enable Secret Detection
                  </span>
                  <p className="text-xs text-gray-500 mt-1">
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
                  <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
                </div>
              </label>
            </div>

            {/* Log Level */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Log Level
              </label>
              <select
                value={logLevel}
                onChange={(e) => setLogLevel(e.target.value)}
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="DEBUG">DEBUG</option>
                <option value="INFO">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ERROR">ERROR</option>
              </select>
              <p className="text-xs text-gray-500 mt-1">Application logging verbosity</p>
            </div>
          </div>
        </div>
        </>
      )}

      {activeTab === "notifications" && (
        <>
        {/* Notification Settings */}
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <Bell className="w-6 h-6 text-purple-500" />
            <h2 className="text-xl font-semibold text-white">Notifications</h2>
          </div>

          <div className="space-y-4">
            {/* Enable Notifications */}
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-gray-300">Enable Notifications</label>
              <button
                onClick={() => setNtfyEnabled(!ntfyEnabled)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  ntfyEnabled ? "bg-green-600" : "bg-red-600"
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    ntfyEnabled ? "translate-x-6" : "translate-x-1"
                  }`}
                />
              </button>
            </div>

            {/* ntfy URL */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">ntfy Server URL</label>
              <input
                type="text"
                value={ntfyUrl}
                onChange={(e) => setNtfyUrl(e.target.value)}
                disabled={!ntfyEnabled}
                autoComplete="off"
                data-lpignore="true"
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
              />
            </div>

            {/* ntfy Topic */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">ntfy Topic</label>
              <input
                type="text"
                value={ntfyTopic}
                onChange={(e) => setNtfyTopic(e.target.value)}
                disabled={!ntfyEnabled}
                autoComplete="off"
                data-lpignore="true"
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
              />
            </div>

            {/* ntfy Authentication Token */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                ntfy Access Token
                <span className="text-xs text-gray-500 ml-2">(optional)</span>
              </label>
              <div className="relative">
                <input
                  type={showNtfyToken ? "text" : "password"}
                  value={ntfyToken}
                  onChange={(e) => setNtfyToken(e.target.value)}
                  disabled={!ntfyEnabled}
                  placeholder="tk_..."
                  autoComplete="new-password"
                  data-lpignore="true"
                  className="w-full px-3 py-2 pr-10 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                />
                <button
                  type="button"
                  onClick={() => setShowNtfyToken(!showNtfyToken)}
                  disabled={!ntfyEnabled}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {showNtfyToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-xs text-gray-500 mt-1">
                Required if your ntfy server has authentication enabled
              </p>
            </div>

            {/* Test Notification */}
            <button
              onClick={handleTestNotification}
              disabled={!ntfyEnabled}
              className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              Send Test Notification
            </button>

            <div className="border-t border-gray-700 pt-4">
              {/* Notify on Scan Complete */}
              <div className="flex items-center justify-between mb-3">
                <label className="text-sm font-medium text-gray-300">Notify on Scan Complete</label>
                <button
                  onClick={() => setNotifyOnScanComplete(!notifyOnScanComplete)}
                  disabled={!ntfyEnabled}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    notifyOnScanComplete && ntfyEnabled ? "bg-green-600" : "bg-red-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      notifyOnScanComplete ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>

              {/* Notify on Critical */}
              <div className="flex items-center justify-between mb-3">
                <label className="text-sm font-medium text-gray-300">Notify on Critical CVEs</label>
                <button
                  onClick={() => setNotifyOnCritical(!notifyOnCritical)}
                  disabled={!ntfyEnabled}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    notifyOnCritical && ntfyEnabled ? "bg-green-600" : "bg-red-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      notifyOnCritical ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>

              {/* Critical Threshold */}
              <div className="mb-3">
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Critical CVE Threshold
                </label>
                <input
                  type="number"
                  value={notifyThresholdCritical}
                  onChange={(e) => setNotifyThresholdCritical(Number(e.target.value))}
                  min={1}
                  disabled={!ntfyEnabled || !notifyOnCritical}
                  className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                />
                <p className="text-xs text-gray-500 mt-1">Alert if X or more critical CVEs found</p>
              </div>

              {/* High Threshold */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  High CVE Threshold
                </label>
                <input
                  type="number"
                  value={notifyThresholdHigh}
                  onChange={(e) => setNotifyThresholdHigh(Number(e.target.value))}
                  min={1}
                  disabled={!ntfyEnabled}
                  className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                />
                <p className="text-xs text-gray-500 mt-1">Alert if X or more high CVEs found</p>
              </div>
            </div>
          </div>
        </div>
        </>
      )}

      {activeTab === "data" && (
        <>
        {/* Data Retention */}
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <Database className="w-6 h-6 text-green-500" />
            <h2 className="text-xl font-semibold text-white">Data Retention</h2>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Keep Scan History (days)
              </label>
              <input
                type="number"
                value={keepScanHistoryDays}
                onChange={(e) => setKeepScanHistoryDays(Number(e.target.value))}
                min={7}
                max={365}
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-500 mt-1">
                Scan history older than this will be automatically deleted
              </p>
            </div>

            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
              <p className="text-sm text-yellow-500">
                <strong>Note:</strong> Container and vulnerability data is always retained. Only scan
                history records are affected.
              </p>
            </div>
          </div>
        </div>
        </>
      )}

      {activeTab === "security" && (
        <>
        {/* Compliance Settings */}
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <FileCheck className="w-6 h-6 text-cyan-500" />
            <h2 className="text-xl font-semibold text-white">Compliance Scanning</h2>
          </div>

          <div className="space-y-4">
            {/* Enable Compliance Scanning */}
            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-gray-300 group-hover:text-white transition-colors">
                    Enable Compliance Scanning
                  </span>
                  <p className="text-xs text-gray-500 mt-1">
                    Automatically run Docker Bench for Security scans on a schedule
                  </p>
                </div>
                <div className="relative">
                  <input
                    type="checkbox"
                    checked={complianceScanEnabled}
                    onChange={(e) => setComplianceScanEnabled(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
                </div>
              </label>
            </div>

            {/* Compliance Scan Schedule */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Compliance Scan Schedule (Cron)
              </label>
              <input
                type="text"
                value={complianceScanSchedule}
                onChange={(e) => setComplianceScanSchedule(e.target.value)}
                disabled={!complianceScanEnabled}
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                placeholder="0 3 * * 0"
              />
              <p className="text-xs text-gray-500 mt-1">Current: Weekly on Sunday at 3:00 AM</p>
            </div>

            {/* Notify on Scan */}
            <div className="border-t border-gray-700 pt-4">
              <div className="flex items-center justify-between mb-3">
                <label className="text-sm font-medium text-gray-300">Notify on Compliance Scan</label>
                <button
                  onClick={() => setComplianceNotifyOnScan(!complianceNotifyOnScan)}
                  disabled={!complianceScanEnabled || !ntfyEnabled}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    complianceNotifyOnScan && complianceScanEnabled && ntfyEnabled ? "bg-green-600" : "bg-red-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      complianceNotifyOnScan ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>

              {/* Notify on Failures */}
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-300">Notify on Critical Failures</label>
                <button
                  onClick={() => setComplianceNotifyOnFailures(!complianceNotifyOnFailures)}
                  disabled={!complianceScanEnabled || !ntfyEnabled}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    complianceNotifyOnFailures && complianceScanEnabled && ntfyEnabled ? "bg-green-600" : "bg-red-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      complianceNotifyOnFailures ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            </div>

            <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-lg p-4">
              <p className="text-sm text-cyan-400">
                <strong>Docker Bench for Security</strong> runs CIS Docker Benchmark compliance checks.
                Manual scans are always available on the Compliance page.
              </p>
            </div>
          </div>
        </div>
        </>
      )}

      {activeTab === "scanning" && (
        <>
        {/* Scanner Offline Resilience Settings */}
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <Database className="w-6 h-6 text-blue-500" />
            <h2 className="text-xl font-semibold text-white">Scanner Offline Resilience</h2>
          </div>

          <div className="space-y-4">
            {/* Skip DB Update When Fresh */}
            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-gray-300 group-hover:text-white transition-colors">
                    Skip Database Updates When Fresh
                  </span>
                  <p className="text-xs text-gray-500 mt-1">
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
                  <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
                </div>
              </label>
            </div>

            {/* Max DB Age Hours */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Maximum Database Age (Hours)
              </label>
              <input
                type="number"
                value={scannerDbMaxAgeHours}
                onChange={(e) => setScannerDbMaxAgeHours(parseInt(e.target.value) || 24)}
                min="1"
                max="168"
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-500 mt-1">
                Maximum age for scanner databases to be considered "fresh" (default: 24 hours)
              </p>
            </div>

            {/* Stale DB Warning Hours */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Stale Database Warning (Hours)
              </label>
              <input
                type="number"
                value={scannerStaleDbWarningHours}
                onChange={(e) => setScannerStaleDbWarningHours(parseInt(e.target.value) || 72)}
                min="1"
                max="720"
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-500 mt-1">
                Show warnings when scanner databases exceed this age (default: 72 hours)
              </p>
            </div>

            {/* Allow Stale DB */}
            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-gray-300 group-hover:text-white transition-colors">
                    Allow Scans with Stale Databases
                  </span>
                  <p className="text-xs text-gray-500 mt-1">
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
                  <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
                </div>
              </label>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
              <p className="text-sm text-blue-400">
                <strong>Offline Resilience:</strong> These settings help VulnForge work better in environments with limited or
                unreliable internet connectivity. Enable "Skip Database Updates When Fresh" to reduce network dependency by ~80%.
              </p>
            </div>
          </div>
        </div>

        {/* UI Preferences */}
        <div className="mb-6 bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <SettingsIcon className="w-6 h-6 text-orange-500" />
            <h2 className="text-xl font-semibold text-white">UI Preferences</h2>
          </div>

          <div className="space-y-4">
            {/* Default Severity Filter */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Default Severity Filter
              </label>
              <select
                value={defaultSeverityFilter}
                onChange={(e) => setDefaultSeverityFilter(e.target.value)}
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical Only</option>
                <option value="high">High & Above</option>
                <option value="medium">Medium & Above</option>
                <option value="low">Low & Above</option>
              </select>
              <p className="text-xs text-gray-500 mt-1">
                Default filter when viewing vulnerabilities
              </p>
            </div>

            {/* Show Fixable Only */}
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium text-gray-300">Show Fixable Only by Default</label>
                <p className="text-xs text-gray-500 mt-1">
                  Only show vulnerabilities with available fixes
                </p>
              </div>
              <button
                onClick={() => setDefaultShowFixableOnly(!defaultShowFixableOnly)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  defaultShowFixableOnly ? "bg-blue-600" : "bg-gray-700"
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    defaultShowFixableOnly ? "translate-x-6" : "translate-x-1"
                  }`}
                />
              </button>
            </div>
          </div>
        </div>
        </>
      )}

      {activeTab === "security" && (
        <>
        {/* KEV Settings */}
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-6 h-6 text-red-500" />
            <h2 className="text-xl font-semibold text-white">KEV (Known Exploited Vulnerabilities)</h2>
          </div>

          <div className="space-y-4">
            {/* Enable KEV Checking */}
            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-gray-300 group-hover:text-white transition-colors">
                    Enable KEV Checking
                  </span>
                  <p className="text-xs text-gray-500 mt-1">
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
                  <div className="w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
                </div>
              </label>
            </div>

            {/* Cache Hours */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Cache Duration (Hours)
              </label>
              <input
                type="number"
                value={kevCacheHours}
                onChange={(e) => setKevCacheHours(parseInt(e.target.value) || 12)}
                disabled={!kevCheckingEnabled}
                min="1"
                max="72"
                className="w-full px-3 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
              />
              <p className="text-xs text-gray-500 mt-1">How long to cache the KEV catalog before refreshing</p>
            </div>

            {/* Last Refresh */}
            {kevLastRefresh && (
              <div className="bg-gray-700/20 border border-gray-700 rounded-lg p-3">
                <p className="text-sm text-gray-300">
                  <strong>Last KEV Refresh:</strong>{" "}
                  <span className="text-gray-400">
                    {new Date(kevLastRefresh).toLocaleString()}
                  </span>
                </p>
              </div>
            )}

            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
              <p className="text-sm text-red-400">
                <strong>KEV vulnerabilities are actively exploited in the wild.</strong> These CVEs have been confirmed
                by CISA to be used in real-world attacks and should be prioritized for immediate remediation.
              </p>
              <a
                href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-block mt-2 text-sm text-red-300 hover:text-red-200 underline"
              >
                View CISA KEV Catalog →
              </a>
            </div>
          </div>
        </div>
        </>
      )}


      {activeTab === "data" && (
        <>
      {/* Database Backup */}
      <div className="mt-6 bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
          <Database className="w-5 h-5 text-purple-500" />
          Database Backup
        </h2>
        <div className="space-y-4">
          <DatabaseBackupSection />
        </div>
      </div>
        </>
      )}

      {/* Info Box - Show on all tabs */}
      <div className="mt-6 bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Clock className="w-5 h-5 text-blue-500 mt-0.5" />
          <div>
            <h3 className="text-sm font-medium text-blue-500 mb-1">Persistent Settings</h3>
            <p className="text-sm text-gray-400">
              All settings are stored in the database and persist across container restarts. Changes take effect
              immediately after saving.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
