import { useState } from 'react';
import { Bell, ChevronDown, ChevronRight, Shield, AlertTriangle, Settings, Settings2 } from 'lucide-react';
import { HelpTooltip } from '@/components/HelpTooltip';

interface EventGroup {
  id: string;
  label: string;
  icon: typeof Bell;
  enabledKey: string;
  events: { key: string; label: string; description: string }[];
}

// VulnForge-specific event groups
const eventGroups: EventGroup[] = [
  {
    id: 'security',
    label: 'Security Alerts',
    icon: Shield,
    enabledKey: 'notify_security_enabled',
    events: [
      { key: 'notify_security_kev', label: 'KEV Detected', description: 'CISA Known Exploited Vulnerabilities found' },
      { key: 'notify_security_critical', label: 'Critical Vulnerabilities', description: 'Critical CVEs exceed threshold' },
      { key: 'notify_security_secrets', label: 'Secrets Detected', description: 'Exposed credentials or API keys found' },
    ],
  },
  {
    id: 'scans',
    label: 'Scan Events',
    icon: AlertTriangle,
    enabledKey: 'notify_scans_enabled',
    events: [
      { key: 'notify_scans_complete', label: 'Scan Complete', description: 'Vulnerability scan batch finished' },
      { key: 'notify_scans_failed', label: 'Scan Failed', description: 'Container scan encountered errors' },
      { key: 'notify_scans_compliance_complete', label: 'Compliance Scan Complete', description: 'Compliance scan finished' },
      { key: 'notify_scans_compliance_failures', label: 'Compliance Failures', description: 'Security compliance checks failed' },
    ],
  },
  {
    id: 'system',
    label: 'System Events',
    icon: Settings,
    enabledKey: 'notify_system_enabled',
    events: [
      { key: 'notify_system_kev_refresh', label: 'KEV Catalog Updated', description: 'CISA KEV catalog refreshed' },
      { key: 'notify_system_backup', label: 'Backup Complete', description: 'Database backup created' },
    ],
  },
];

interface EventNotificationsCardProps {
  settings: Record<string, unknown>;
  onSettingChange: (key: string, value: boolean) => void;
  onTextChange: (key: string, value: string) => void;
  saving: boolean;
  hasEnabledService: boolean;
}

export function EventNotificationsCard({
  settings,
  onSettingChange,
  onTextChange,
  saving,
  hasEnabledService,
}: EventNotificationsCardProps) {
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(['security', 'scans']));
  const [showAdvanced, setShowAdvanced] = useState(false);

  const toggleGroup = (groupId: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  };

  const getEnabledCount = (group: EventGroup): { enabled: number; total: number } => {
    const groupEnabled = settings[group.enabledKey] === 'true' || settings[group.enabledKey] === true;
    if (!groupEnabled) {
      return { enabled: 0, total: group.events.length };
    }
    const enabled = group.events.filter(
      (e) => settings[e.key] === 'true' || settings[e.key] === true
    ).length;
    return { enabled, total: group.events.length };
  };

  if (!hasEnabledService) {
    return (
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
        <div className="flex items-center gap-3 mb-4">
          <Bell className="w-6 h-6 text-vuln-text-muted" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">Event Notifications</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Configure which events trigger notifications
            </p>
          </div>
        </div>
        <div className="bg-vuln-surface-light/50 border border-vuln-border rounded-lg p-4 text-center">
          <p className="text-vuln-text-muted text-sm">
            Enable at least one notification service to configure event notifications.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <Bell className="w-6 h-6 text-blue-500" />
          <div>
            <h2 className="text-lg font-semibold text-vuln-text">Event Notifications</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Configure which events trigger notifications
            </p>
          </div>
        </div>
        <HelpTooltip content="Select which VulnForge events should send notifications. Enable a category to activate its events, then toggle individual events as needed. Notifications are sent to all enabled services." />
      </div>

      <div className="space-y-3">
        {eventGroups.map((group) => {
          const Icon = group.icon;
          const isExpanded = expandedGroups.has(group.id);
          const isGroupEnabled = settings[group.enabledKey] === 'true' || settings[group.enabledKey] === true;
          const { enabled, total } = getEnabledCount(group);

          return (
            <div
              key={group.id}
              className="border border-vuln-border rounded-lg overflow-hidden"
            >
              {/* Group Header */}
              <div className="flex items-center justify-between p-3 bg-vuln-surface-light/50">
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => toggleGroup(group.id)}
                    className="text-vuln-text-muted hover:text-vuln-text transition-colors"
                  >
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                  </button>
                  <Icon className="w-5 h-5 text-vuln-text-muted" />
                  <span className="font-medium text-vuln-text">{group.label}</span>
                  {!isExpanded && (
                    <span className="text-xs text-vuln-text-muted">
                      ({enabled}/{total} enabled)
                    </span>
                  )}
                </div>
                <label className="flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isGroupEnabled}
                    onChange={(e) => onSettingChange(group.enabledKey, e.target.checked)}
                    disabled={saving}
                    className="sr-only peer"
                  />
                  <div className="w-10 h-5 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600 relative"></div>
                </label>
              </div>

              {/* Events List */}
              {isExpanded && (
                <div className="divide-y divide-vuln-border">
                  {group.events.map((event) => {
                    const isEventEnabled =
                      isGroupEnabled &&
                      (settings[event.key] === 'true' || settings[event.key] === true);

                    return (
                      <div
                        key={event.key}
                        className={`flex items-center justify-between p-3 pl-12 ${
                          !isGroupEnabled ? 'opacity-50' : ''
                        }`}
                      >
                        <div>
                          <span className="text-sm font-medium text-vuln-text">
                            {event.label}
                          </span>
                          <p className="text-xs text-vuln-text-muted mt-0.5">
                            {event.description}
                          </p>
                        </div>
                        <label className="flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={isEventEnabled}
                            onChange={(e) => onSettingChange(event.key, e.target.checked)}
                            disabled={saving || !isGroupEnabled}
                            className="sr-only peer"
                          />
                          <div className="w-10 h-5 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600 peer-disabled:opacity-50 relative"></div>
                        </label>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Advanced Settings */}
      <div className="mt-4 border border-vuln-border rounded-lg overflow-hidden">
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-3 w-full p-3 bg-vuln-surface-light/50 text-left"
        >
          <Settings2 className="w-5 h-5 text-vuln-text-muted" />
          <div className="flex-1">
            <span className="text-sm font-medium text-vuln-text">Advanced</span>
            <p className="text-xs text-vuln-text-muted">Retry settings for high-priority notifications</p>
          </div>
          {showAdvanced ? (
            <ChevronDown className="w-4 h-4 text-vuln-text-muted" />
          ) : (
            <ChevronRight className="w-4 h-4 text-vuln-text-muted" />
          )}
        </button>

        {showAdvanced && (
          <div className="p-3 space-y-3">
            <div className="flex items-center justify-between gap-4">
              <div className="flex-1 min-w-0">
                <label className="text-sm text-vuln-text">Retry Attempts</label>
                <p className="text-xs text-vuln-text-muted">Max retries for urgent/high priority events</p>
              </div>
              <input
                type="number"
                min="1"
                max="10"
                value={String(settings.notification_retry_attempts ?? '3')}
                onChange={(e) => onTextChange('notification_retry_attempts', e.target.value)}
                disabled={saving}
                className="w-20 px-2 py-1 text-sm bg-vuln-bg border border-vuln-border rounded text-vuln-text focus:outline-none focus:border-blue-500"
              />
            </div>
            <div className="flex items-center justify-between gap-4">
              <div className="flex-1 min-w-0">
                <label className="text-sm text-vuln-text">Retry Delay (seconds)</label>
                <p className="text-xs text-vuln-text-muted">Base delay between retry attempts</p>
              </div>
              <input
                type="number"
                min="0.5"
                max="30"
                step="0.5"
                value={String(settings.notification_retry_delay ?? '2.0')}
                onChange={(e) => onTextChange('notification_retry_delay', e.target.value)}
                disabled={saving}
                className="w-20 px-2 py-1 text-sm bg-vuln-bg border border-vuln-border rounded text-vuln-text focus:outline-none focus:border-blue-500"
              />
            </div>
            <p className="text-xs text-vuln-text-muted italic">
              Retries only apply to urgent/high priority events (security alerts)
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
