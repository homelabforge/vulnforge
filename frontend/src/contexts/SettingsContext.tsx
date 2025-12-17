/**
 * Settings Context for VulnForge
 * Provides global access to settings including timezone
 */

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { settingsApi, Setting } from '../lib/api';

interface SettingsContextType {
  timezone: string;
  isLoading: boolean;
  settings: Record<string, string>;
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined);

interface SettingsProviderProps {
  children: ReactNode;
}

export function SettingsProvider({ children }: SettingsProviderProps) {
  const [timezone, setTimezone] = useState<string>('UTC');
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(true);

  // Fetch settings on mount
  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const data = await settingsApi.getAll();
        const settingsMap: Record<string, string> = {};
        data.forEach((s: Setting) => {
          settingsMap[s.key] = s.value;
        });
        setSettings(settingsMap);

        // Set timezone from settings
        if (settingsMap.timezone) {
          setTimezone(settingsMap.timezone);
        }
      } catch (error) {
        console.warn('Failed to fetch settings:', error);
        // Fall back to UTC
      } finally {
        setIsLoading(false);
      }
    };

    fetchSettings();

    // Re-fetch settings periodically to pick up changes
    const interval = setInterval(fetchSettings, 60000); // Every 60 seconds
    return () => clearInterval(interval);
  }, []);

  const value: SettingsContextType = {
    timezone,
    isLoading,
    settings,
  };

  return (
    <SettingsContext.Provider value={value}>
      {children}
    </SettingsContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components -- Hook export is intended alongside Provider
export function useTimezone(): string {
  const context = useContext(SettingsContext);
  if (context === undefined) {
    throw new Error('useTimezone must be used within a SettingsProvider');
  }
  return context.timezone;
}

// eslint-disable-next-line react-refresh/only-export-components -- Hook export is intended alongside Provider
export function useGlobalSettings(): SettingsContextType {
  const context = useContext(SettingsContext);
  if (context === undefined) {
    throw new Error('useGlobalSettings must be used within a SettingsProvider');
  }
  return context;
}
