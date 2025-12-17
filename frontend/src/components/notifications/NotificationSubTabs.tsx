import { Bell, Radio, Send, Hash, MessageSquare, AtSign, Mail } from 'lucide-react';

export type NotificationSubTab = 'ntfy' | 'gotify' | 'pushover' | 'slack' | 'discord' | 'telegram' | 'email';

interface NotificationSubTabsProps {
  activeSubTab: NotificationSubTab;
  onSubTabChange: (tab: NotificationSubTab) => void;
  enabledServices: Record<NotificationSubTab, boolean>;
}

const subTabs: { id: NotificationSubTab; label: string; icon: typeof Bell }[] = [
  { id: 'ntfy', label: 'ntfy', icon: Bell },
  { id: 'gotify', label: 'Gotify', icon: Radio },
  { id: 'pushover', label: 'Pushover', icon: Send },
  { id: 'slack', label: 'Slack', icon: Hash },
  { id: 'discord', label: 'Discord', icon: MessageSquare },
  { id: 'telegram', label: 'Telegram', icon: AtSign },
  { id: 'email', label: 'Email', icon: Mail },
];

export function NotificationSubTabs({ activeSubTab, onSubTabChange, enabledServices }: NotificationSubTabsProps) {
  return (
    <div className="flex flex-wrap gap-2 p-1 bg-vuln-surface/50 rounded-lg border border-vuln-border">
      {subTabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeSubTab === tab.id;
        const isEnabled = enabledServices[tab.id];

        return (
          <button
            key={tab.id}
            onClick={() => onSubTabChange(tab.id)}
            className={`flex items-center gap-2 px-3 py-2 rounded-md transition-colors ${
              isActive
                ? 'bg-blue-600/20 text-blue-400'
                : 'text-vuln-text-muted hover:text-vuln-text hover:bg-vuln-surface-light'
            }`}
          >
            <Icon className="w-4 h-4" />
            <span className="text-sm font-medium">{tab.label}</span>
            {isEnabled && (
              <span className="w-2 h-2 rounded-full bg-green-400" title="Enabled" />
            )}
          </button>
        );
      })}
    </div>
  );
}
