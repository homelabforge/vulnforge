import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { settingsApi } from '../lib/api';

type Theme = 'light' | 'dark';

interface ThemeContextType {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  isLoading: boolean;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [theme, setThemeState] = useState<Theme>('light');
  const [isLoading, setIsLoading] = useState(true);

  // Initialize theme on mount
  useEffect(() => {
    const initializeTheme = async () => {
      try {
        // 1. Check localStorage first (instant - already applied by index.html script)
        const localTheme = localStorage.getItem('theme') as Theme | null;

        if (localTheme && (localTheme === 'light' || localTheme === 'dark')) {
          setThemeState(localTheme);
        }

        // 2. Sync with database (for cross-device consistency)
        try {
          const data = await settingsApi.getByKey('theme');
          const dbTheme = data.value as Theme;

          // If database theme differs from local, use database (cross-device sync)
          if (dbTheme && (dbTheme === 'light' || dbTheme === 'dark') && dbTheme !== localTheme) {
            applyTheme(dbTheme);
            setThemeState(dbTheme);
            localStorage.setItem('theme', dbTheme);
          }
        } catch {
          // Settings key might not exist yet - that's fine, use localStorage/default
          console.debug('Theme setting not found in database, using localStorage');
        }
      } catch (error) {
        console.warn('Failed to initialize theme:', error);
        // Continue with localStorage or default theme
      } finally {
        setIsLoading(false);
      }
    };

    initializeTheme();
  }, []);

  // Apply theme to DOM
  const applyTheme = (newTheme: Theme) => {
    const html = document.documentElement;

    if (newTheme === 'light') {
      html.classList.add('light');
      html.classList.remove('dark');
    } else {
      html.classList.add('dark');
      html.classList.remove('light');
    }
  };

  // Set theme with dual persistence
  const setTheme = async (newTheme: Theme) => {
    // 1. Apply immediately to DOM
    applyTheme(newTheme);
    setThemeState(newTheme);

    // 2. Save to localStorage (instant)
    localStorage.setItem('theme', newTheme);

    // 3. Save to database (async, for cross-device sync)
    try {
      await settingsApi.update('theme', newTheme);
    } catch (error) {
      console.warn('Failed to save theme to database:', error);
      // Not critical - theme is still saved locally
    }
  };

  const value: ThemeContextType = {
    theme,
    setTheme,
    isLoading,
  };

  // Don't block rendering - FOUC is prevented by index.html script
  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components -- Hook export is intended alongside Provider
export function useTheme(): ThemeContextType {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}
