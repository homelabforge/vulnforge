/**
 * Login Page for VulnForge
 *
 * Handles user authentication via:
 * - Local username/password login
 * - OIDC/SSO login (if enabled)
 *
 * Supports returnUrl query parameter for post-login redirect.
 */

import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { RefreshCw, Eye, EyeOff, LogIn, Shield } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, oidcEnabled, login } = useAuth();

  // Form state
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Parse returnUrl from query params
  const searchParams = new URLSearchParams(location.search);
  const returnUrl = searchParams.get('returnUrl') || '/';

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate(decodeURIComponent(returnUrl), { replace: true });
    }
  }, [isAuthenticated, returnUrl, navigate]);

  // Handle local login
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      setIsSubmitting(true);
      await login(username, password);

      // Redirect to return URL on success
      navigate(decodeURIComponent(returnUrl), { replace: true });
    } catch {
      // Error already handled by login() in AuthContext
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle SSO login
  const handleSSOLogin = () => {
    // Backend OIDC flow doesn't support returnUrl currently
    // User will always return to "/" after OIDC callback
    window.location.href = '/api/v1/user-auth/oidc/login';
  };

  // Handle Enter key press
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isSubmitting) {
      handleSubmit(e as unknown as React.FormEvent);
    }
  };

  return (
    <div className="min-h-screen bg-vuln-bg flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-8 shadow-lg">
          {/* Header */}
          <div className="mb-6 text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-4">
              <Shield className="w-8 h-8 text-primary" />
            </div>
            <h1 className="text-2xl font-bold text-vuln-text mb-2">Sign In</h1>
            <p className="text-vuln-text-muted">Welcome to VulnForge</p>
          </div>

          {/* Login Form */}
          <form onSubmit={handleSubmit} onKeyDown={handleKeyDown} className="space-y-4">
            {/* Username */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-vuln-text mb-1">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={isSubmitting}
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary disabled:opacity-50 transition-colors"
                required
                autoComplete="username"
              />
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-vuln-text mb-1">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isSubmitting}
                  aria-label="Password"
                  aria-describedby="password-toggle"
                  className="w-full px-3 py-2 pr-10 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary disabled:opacity-50 transition-colors"
                  required
                  autoComplete="current-password"
                />
                <button
                  id="password-toggle"
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {/* Login Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg font-medium flex items-center justify-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Logging in...
                </>
              ) : (
                <>
                  <LogIn className="w-4 h-4" />
                  Login
                </>
              )}
            </button>
          </form>

          {/* SSO Option */}
          {oidcEnabled && (
            <>
              <div className="relative my-6">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-vuln-border"></div>
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-2 bg-vuln-surface text-vuln-text-muted">Or</span>
                </div>
              </div>

              <button
                type="button"
                onClick={handleSSOLogin}
                disabled={isSubmitting}
                className="w-full px-4 py-2 bg-vuln-surface-light hover:bg-vuln-border text-vuln-text border border-vuln-border rounded-lg font-medium flex items-center justify-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <LogIn className="w-4 h-4" />
                Login with SSO
              </button>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="mt-4 text-center">
          <p className="text-vuln-text-muted text-sm">
            Secure container vulnerability scanning and remediation
          </p>
        </div>
      </div>
    </div>
  );
}
