import { z } from "zod";
import {
  safeParseInt,
  integerWithBounds,
  enhancedCronExpression,
  urlOrEmpty,
  jsonArrayString,
  httpHeaderName,
  apiKeysJsonString,
  basicAuthUsersJsonString,
} from "./shared";

// Constants for dropdowns
export const LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR"] as const;
export const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low"] as const;
export const AUTH_PROVIDERS = ["none", "authentik", "custom_headers", "api_key", "basic_auth"] as const;

export const TIMEZONE_PRESETS = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "Europe/London",
  "Europe/Paris",
  "Asia/Tokyo",
  "Asia/Shanghai",
  "Australia/Sydney",
] as const;

// Individual field schemas for validation on change
export const settingsFieldSchemas = {
  // Scan settings - use enhanced cron with range validation
  scan_schedule: enhancedCronExpression,
  scan_timeout: integerWithBounds(60, 600, 300),
  parallel_scans: integerWithBounds(1, 50, 3),

  // Notification thresholds
  notify_threshold_critical: integerWithBounds(1, 100, 1),
  notify_threshold_high: integerWithBounds(1, 100, 10),

  // Data retention
  keep_scan_history_days: integerWithBounds(1, 365, 90),

  // KEV settings
  kev_cache_hours: integerWithBounds(1, 72, 12),

  // Scanner offline resilience
  scanner_db_max_age_hours: integerWithBounds(1, 168, 24),
  scanner_stale_db_warning_hours: integerWithBounds(1, 720, 72),

  // URLs
  ntfy_url: urlOrEmpty,

  // JSON arrays with structure validation
  auth_api_keys: apiKeysJsonString,
  auth_basic_users: basicAuthUsersJsonString,
  auth_admin_usernames: jsonArrayString, // Simple string array, no structure needed

  // HTTP header names
  auth_authentik_header_username: httpHeaderName,
  auth_authentik_header_email: httpHeaderName,
  auth_authentik_header_groups: httpHeaderName,
  auth_custom_header_username: httpHeaderName,
  auth_custom_header_email: httpHeaderName,
  auth_custom_header_groups: httpHeaderName,

  // Enums
  log_level: z.enum(LOG_LEVELS),
  default_severity_filter: z.enum(SEVERITY_FILTERS),
  auth_provider: z.enum(AUTH_PROVIDERS),
};

// Full settings schema (for reference/future use)
export const settingsSchema = z.object({
  // System settings
  timezone: z.string().min(1),
  log_level: z.enum(LOG_LEVELS),

  // Scan settings
  scan_schedule: enhancedCronExpression,
  scan_timeout: integerWithBounds(60, 600, 300),
  parallel_scans: integerWithBounds(1, 50, 3),
  enable_secret_scanning: z.boolean(),

  // Notification settings
  ntfy_enabled: z.boolean(),
  ntfy_url: urlOrEmpty,
  ntfy_topic: z.string(),
  ntfy_token: z.string(),
  notify_on_scan_complete: z.boolean(),
  notify_on_critical: z.boolean(),
  notify_threshold_critical: integerWithBounds(1, 100, 1),
  notify_threshold_high: integerWithBounds(1, 100, 10),

  // Data retention
  keep_scan_history_days: integerWithBounds(1, 365, 90),

  // UI preferences
  default_severity_filter: z.enum(SEVERITY_FILTERS),
  default_show_fixable_only: z.boolean(),

  // Compliance settings
  compliance_scan_enabled: z.boolean(),
  compliance_scan_schedule: enhancedCronExpression,
  compliance_notify_on_scan: z.boolean(),
  compliance_notify_on_failures: z.boolean(),

  // KEV settings
  kev_checking_enabled: z.boolean(),
  kev_cache_hours: integerWithBounds(1, 72, 12),

  // Scanner offline resilience
  scanner_db_max_age_hours: integerWithBounds(1, 168, 24),
  scanner_skip_db_update_when_fresh: z.boolean(),
  scanner_allow_stale_db: z.boolean(),
  scanner_stale_db_warning_hours: integerWithBounds(1, 720, 72),

  // Authentication settings
  auth_enabled: z.boolean(),
  auth_provider: z.enum(AUTH_PROVIDERS),
  auth_authentik_header_username: httpHeaderName,
  auth_authentik_header_email: httpHeaderName,
  auth_authentik_header_groups: httpHeaderName,
  auth_custom_header_username: httpHeaderName,
  auth_custom_header_email: httpHeaderName,
  auth_custom_header_groups: httpHeaderName,
  auth_api_keys: apiKeysJsonString,
  auth_basic_users: basicAuthUsersJsonString,
  auth_admin_group: z.string(),
  auth_admin_usernames: jsonArrayString,
});

export type SettingsFormData = z.infer<typeof settingsSchema>;

/**
 * Safe integer parsing helper specifically for settings.
 * Returns the default value if parsing fails or value is NaN.
 */
export function parseSettingInt(value: string | undefined, defaultValue: number): number {
  return safeParseInt(value, defaultValue) ?? defaultValue;
}

/**
 * Validate a single field value against its schema.
 * Returns { success: true, data } or { success: false, error }.
 */
export function validateSettingField<K extends keyof typeof settingsFieldSchemas>(
  field: K,
  value: unknown
): { success: true; data: z.output<(typeof settingsFieldSchemas)[K]> } | { success: false; error: string } {
  const schema = settingsFieldSchemas[field];
  const result = schema.safeParse(value);

  if (result.success) {
    return { success: true, data: result.data as z.output<(typeof settingsFieldSchemas)[K]> };
  }

  return {
    success: false,
    error: result.error.issues[0]?.message || "Invalid value"
  };
}
