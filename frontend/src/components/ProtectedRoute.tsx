/**
 * ProtectedRoute Component for VulnForge
 *
 * Route guard that protects pages based on authentication status.
 *
 * Behavior:
 * - Shows loading spinner while checking auth
 * - Allows access if user_auth_mode is "none" (no auth required)
 * - Redirects to /setup if auth enabled but setup not complete
 * - Redirects to /login if not authenticated (with returnUrl)
 * - Renders children if authenticated
 */

import { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

interface ProtectedRouteProps {
  children: ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, authMode, setupComplete } = useAuth();
  const location = useLocation();

  // Still checking auth status - show minimal spinner
  if (isLoading) {
    return (
      <div className="min-h-screen bg-vuln-bg flex items-center justify-center">
        <RefreshCw className="animate-spin text-primary" size={32} />
      </div>
    );
  }

  // Auth disabled - allow access to all routes (no setup needed)
  if (authMode === "none") {
    return <>{children}</>;
  }

  // Auth is enabled - check if setup is complete
  if (!setupComplete) {
    return <Navigate to="/setup" replace />;
  }

  // Auth required but user not authenticated - redirect to login
  if (!isAuthenticated) {
    // Save return URL for redirect after successful login
    const returnUrl = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?returnUrl=${returnUrl}`} replace />;
  }

  // User is authenticated - render protected content
  return <>{children}</>;
}
