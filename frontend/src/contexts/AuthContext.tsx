/**
 * Authentication Context for VulnForge
 *
 * Manages user authentication state including:
 * - User profile and session status
 * - Auth mode (none, local, OIDC)
 * - Login/logout flows
 * - Profile updates and password changes
 *
 * Pattern follows ThemeContext.tsx for consistency
 */

import { createContext, useState, useEffect, useContext, ReactNode } from 'react';
import { toast } from 'sonner';
import { userAuthApi } from '../lib/api';
import type { UserProfile } from '../types/auth';

// ============================================================================
// Context Type Definition
// ============================================================================

interface AuthContextType {
  // State
  user: UserProfile | null;
  authMode: "none" | "local" | "oidc";
  isAuthenticated: boolean;
  isLoading: boolean;
  setupComplete: boolean;
  oidcEnabled: boolean;

  // Actions
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
  updateProfile: (email: string, fullName: string) => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// ============================================================================
// Auth Provider Component
// ============================================================================

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [authMode, setAuthMode] = useState<"none" | "local" | "oidc">("none");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [setupComplete, setSetupComplete] = useState(false);
  const [oidcEnabled, setOidcEnabled] = useState(false);

  // Initialize authentication state on mount
  useEffect(() => {
    let mounted = true;

    async function initialize() {
      try {
        setIsLoading(true);

        // 1. Check auth status
        const status = await userAuthApi.getStatus();
        if (!mounted) return;

        setSetupComplete(status.setup_complete);
        setAuthMode(status.auth_mode);
        setOidcEnabled(status.oidc_enabled);

        // 2. If setup not complete, stop here
        if (!status.setup_complete) {
          if (mounted) setIsLoading(false);
          return;
        }

        // 3. If auth disabled, mark as authenticated
        if (status.auth_mode === "none") {
          if (mounted) {
            setIsAuthenticated(true);
            setIsLoading(false);
          }
          return;
        }

        // 4. Check if logged in
        try {
          const profile = await userAuthApi.getMe();
          if (!mounted) return;

          setUser(profile);
          setIsAuthenticated(true);
          sessionStorage.setItem('wasAuthenticated', 'true');
        } catch {
          // 401 = not logged in
          if (mounted) setIsAuthenticated(false);
        }
      } catch (error) {
        if (mounted) {
          // If auth endpoints don't exist (404), default to auth disabled
          // This allows the app to work when authentication is not yet implemented
          const errorMessage = error instanceof Error ? error.message : String(error);

          if (errorMessage.includes('404') || errorMessage.includes('Not Found')) {
            console.warn('User authentication endpoints not found - defaulting to auth disabled mode');
            setSetupComplete(true);
            setAuthMode('none');
            setIsAuthenticated(true);
          } else {
            console.error('Failed to check user authentication status:', error);
            toast.error('Failed to check authentication status');
          }
        }
      } finally {
        if (mounted) setIsLoading(false);
      }
    }

    initialize();

    return () => {
      mounted = false; // Cleanup to prevent state updates on unmounted component
    };
  }, []);

  // Listen for 401 errors from API calls (session expired)
  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'userAuth:401') {
        setIsAuthenticated(false);
        setUser(null);
        toast.error('Session expired. Please login again.');
        // ProtectedRoute will handle redirect
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  // ============================================================================
  // Auth Actions
  // ============================================================================

  const login = async (username: string, password: string) => {
    try {
      await userAuthApi.login({ username, password });
      // JWT cookie now set by backend

      // Fetch user profile
      const profile = await userAuthApi.getMe();
      setUser(profile);
      setIsAuthenticated(true);
      sessionStorage.setItem('wasAuthenticated', 'true');
      toast.success('Logged in successfully');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Invalid username or password';
      toast.error(errorMessage);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await userAuthApi.logout();
      setUser(null);
      setIsAuthenticated(false);
      sessionStorage.removeItem('wasAuthenticated');
      toast.success('Logged out successfully');
    } catch (error) {
      console.error('Logout error:', error);
      // Clear state anyway
      setUser(null);
      setIsAuthenticated(false);
      sessionStorage.removeItem('wasAuthenticated');
    }
  };

  const checkAuth = async () => {
    try {
      const status = await userAuthApi.getStatus();
      setSetupComplete(status.setup_complete);
      setAuthMode(status.auth_mode);
      setOidcEnabled(status.oidc_enabled);

      if (status.auth_mode === "none") {
        setIsAuthenticated(true);
        return;
      }

      if (status.setup_complete) {
        try {
          const profile = await userAuthApi.getMe();
          setUser(profile);
          setIsAuthenticated(true);
          sessionStorage.setItem('wasAuthenticated', 'true');
        } catch {
          setIsAuthenticated(false);
          setUser(null);
        }
      }
    } catch (error) {
      console.error('Failed to check auth:', error);
    }
  };

  const updateProfile = async (email: string, fullName: string) => {
    try {
      const updatedProfile = await userAuthApi.updateProfile({
        email,
        full_name: fullName,
      });
      setUser(updatedProfile);
      toast.success('Profile updated successfully');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to update profile';
      toast.error(errorMessage);
      throw error;
    }
  };

  const changePassword = async (currentPassword: string, newPassword: string) => {
    try {
      await userAuthApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      toast.success('Password changed successfully');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to change password';
      toast.error(errorMessage);
      throw error;
    }
  };

  // ============================================================================
  // Context Value
  // ============================================================================

  const value: AuthContextType = {
    user,
    authMode,
    isAuthenticated,
    isLoading,
    setupComplete,
    oidcEnabled,
    login,
    logout,
    checkAuth,
    updateProfile,
    changePassword,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// Custom hook to use the auth context
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

export { AuthContext };
export type { AuthContextType };
