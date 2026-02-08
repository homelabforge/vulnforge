/**
 * Settings Page - Thin shell that renders the active settings tab.
 */

import { useState, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Settings as SettingsIcon, RefreshCw, Bell, Shield, Database, Info, Lock } from "lucide-react";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { useSettings, useBulkUpdateSettings } from "@/hooks/useVulnForge";
import { SystemTab } from "./settings/SystemTab";
import { ScanningTab } from "./settings/ScanningTab";
import { NotificationsTab } from "./settings/NotificationsTab";
import { SecurityTab } from "./settings/SecurityTab";
import { DataTab } from "./settings/DataTab";

type SettingsTab = "system" | "scanning" | "notifications" | "security" | "data";

const TABS: { key: SettingsTab; label: string; icon: typeof SettingsIcon }[] = [
  { key: "system", label: "System", icon: SettingsIcon },
  { key: "scanning", label: "Scanning", icon: Shield },
  { key: "notifications", label: "Notifications", icon: Bell },
  { key: "security", label: "Security", icon: Lock },
  { key: "data", label: "Data & Maintenance", icon: Database },
];

export function Settings() {
  const navigate = useNavigate();
  const { data: settings, isLoading } = useSettings();
  const bulkUpdateMutation = useBulkUpdateSettings();
  const [activeTab, setActiveTab] = useState<SettingsTab>("system");

  // Convert settings array to map for tab components
  const settingsMap = useMemo(() => {
    const map: Record<string, string> = {};
    settings?.forEach((s) => {
      map[s.key] = s.value;
    });
    return map;
  }, [settings]);

  // Shared save handler for all tabs
  const handleSave = useCallback((payload: Record<string, string>) => {
    bulkUpdateMutation.mutate(payload, {
      onSuccess: () => toast.success("Settings saved"),
      onError: (error) => handleApiError(error, "Failed to save settings"),
    });
  }, [bulkUpdateMutation]);

  if (isLoading) {
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
          {TABS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`px-4 py-2 font-medium transition-colors relative ${
                activeTab === key
                  ? "text-blue-400 border-b-2 border-blue-400"
                  : "text-vuln-text-muted hover:text-vuln-text"
              }`}
            >
              <Icon className="w-4 h-4 inline-block mr-2" />
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === "system" && <SystemTab settingsMap={settingsMap} onSave={handleSave} />}
      {activeTab === "scanning" && <ScanningTab settingsMap={settingsMap} onSave={handleSave} />}
      {activeTab === "notifications" && <NotificationsTab settingsMap={settingsMap} onSave={handleSave} isSaving={bulkUpdateMutation.isPending} />}
      {activeTab === "security" && <SecurityTab settingsMap={settingsMap} onSave={handleSave} />}
      {activeTab === "data" && <DataTab settingsMap={settingsMap} onSave={handleSave} />}
    </div>
  );
}
