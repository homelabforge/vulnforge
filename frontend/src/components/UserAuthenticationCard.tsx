/**
 * User Authentication Card - Modern UI for authentication management
 * Replicates TideWatch design with modals for Edit Profile, Change Password, and OIDC config
 */

import { useState, useEffect } from "react";
import { Shield, User, Lock, X, Eye, EyeOff, Check, AlertCircle, RefreshCw } from "lucide-react";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useAuth } from "@/hooks/useAuth";
import { toast } from "sonner";
import { settingsApi, userAuthApi } from "@/lib/api";

export function UserAuthenticationCard() {
  const { user, authMode } = useAuth();

  // Modal visibility states
  const [editProfileModalOpen, setEditProfileModalOpen] = useState(false);
  const [changePasswordModalOpen, setChangePasswordModalOpen] = useState(false);
  const [oidcConfigModalOpen, setOidcConfigModalOpen] = useState(false);

  // Edit Profile states
  const [profileEmail, setProfileEmail] = useState("");
  const [profileFullName, setProfileFullName] = useState("");
  const [savingProfile, setSavingProfile] = useState(false);

  // Change Password states
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);

  // OIDC Config states
  const [oidcEnabled, setOidcEnabled] = useState(false);
  const [oidcProviderName, setOidcProviderName] = useState("");
  const [oidcIssuerUrl, setOidcIssuerUrl] = useState("");
  const [oidcClientId, setOidcClientId] = useState("");
  const [oidcClientSecret, setOidcClientSecret] = useState("");
  const [oidcScopes, setOidcScopes] = useState("openid profile email");
  const [oidcUsernameClaim, setOidcUsernameClaim] = useState("preferred_username");
  const [oidcEmailClaim, setOidcEmailClaim] = useState("email");
  const [showOidcSecret, setShowOidcSecret] = useState(false);
  const [testingOidc, setTestingOidc] = useState(false);
  const [savingOidc, setSavingOidc] = useState(false);

  // Initialize profile form when modal opens
  useEffect(() => {
    if (editProfileModalOpen && user) {
      setProfileEmail(user.email || "");
      setProfileFullName(user.full_name || "");
    }
  }, [editProfileModalOpen, user]);

  // Load OIDC settings when modal opens
  useEffect(() => {
    if (oidcConfigModalOpen) {
      loadOidcSettings();
    }
  }, [oidcConfigModalOpen]);

  const loadOidcSettings = async () => {
    try {
      const settings = await settingsApi.getAll();
      const settingsMap = new Map(settings.map((s: { key: string; value: string }) => [s.key, s.value]));

      setOidcEnabled(settingsMap.get("user_auth_oidc_enabled") === "true");
      setOidcProviderName(settingsMap.get("user_auth_oidc_provider_name") || "");
      setOidcIssuerUrl(settingsMap.get("user_auth_oidc_issuer_url") || "");
      setOidcClientId(settingsMap.get("user_auth_oidc_client_id") || "");
      setOidcClientSecret(settingsMap.get("user_auth_oidc_client_secret") || "");
      setOidcScopes(settingsMap.get("user_auth_oidc_scopes") || "openid profile email");
      setOidcUsernameClaim(settingsMap.get("user_auth_oidc_username_claim") || "preferred_username");
      setOidcEmailClaim(settingsMap.get("user_auth_oidc_email_claim") || "email");
    } catch (error) {
      console.error("Failed to load OIDC settings:", error);
      toast.error("Failed to load OIDC settings");
    }
  };

  // Update profile handler
  const handleUpdateProfile = async () => {
    try {
      setSavingProfile(true);
      await userAuthApi.updateProfile({ email: profileEmail, full_name: profileFullName });
      toast.success("Profile updated successfully");
      setEditProfileModalOpen(false);
      // Refresh page to reload user data
      setTimeout(() => window.location.reload(), 500);
    } catch {
      toast.error("Failed to update profile");
    } finally {
      setSavingProfile(false);
    }
  };

  // Password validation
  const validatePassword = (password: string) => {
    return {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /\d/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    };
  };

  const passwordValidation = validatePassword(newPassword);
  const passwordsMatch = newPassword === confirmPassword && confirmPassword.length > 0;
  const isPasswordValid =
    passwordValidation.length &&
    passwordValidation.uppercase &&
    passwordValidation.lowercase &&
    passwordValidation.number &&
    passwordValidation.special &&
    passwordsMatch;

  // Change password handler
  const handleChangePassword = async () => {
    if (!isPasswordValid) return;

    try {
      setChangingPassword(true);
      await userAuthApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      toast.success("Password changed successfully");
      setChangePasswordModalOpen(false);
      // Clear form
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch {
      toast.error("Failed to change password");
    } finally {
      setChangingPassword(false);
    }
  };

  // Test OIDC connection handler
  const handleTestOidcConnection = async () => {
    try {
      setTestingOidc(true);
      const result = await userAuthApi.testOidcConnection(oidcIssuerUrl, oidcClientId, oidcClientSecret);

      if (result.success) {
        toast.success("OIDC connection successful!");
      } else {
        toast.error(`OIDC connection failed: ${result.errors.join(", ")}`);
      }
    } catch (error) {
      console.error("Failed to test OIDC:", error);
      toast.error("Failed to test OIDC connection");
    } finally {
      setTestingOidc(false);
    }
  };

  // Save OIDC config handler
  const handleSaveOidcConfig = async () => {
    try {
      setSavingOidc(true);

      await settingsApi.bulkUpdate({
        user_auth_oidc_enabled: oidcEnabled.toString(),
        user_auth_oidc_provider_name: oidcProviderName,
        user_auth_oidc_issuer_url: oidcIssuerUrl,
        user_auth_oidc_client_id: oidcClientId,
        user_auth_oidc_client_secret: oidcClientSecret,
        user_auth_oidc_scopes: oidcScopes,
        user_auth_oidc_username_claim: oidcUsernameClaim,
        user_auth_oidc_email_claim: oidcEmailClaim,
      });

      toast.success("OIDC configuration saved successfully");
      setOidcConfigModalOpen(false);
    } catch (error) {
      console.error("Failed to save OIDC config:", error);
      toast.error("Failed to save OIDC configuration");
    } finally {
      setSavingOidc(false);
    }
  };

  // Enable local auth handler
  const handleEnableLocalAuth = async () => {
    try {
      await settingsApi.update("user_auth_mode", "local");
      toast.success("Local authentication enabled. Redirecting to login...");
      setTimeout(() => window.location.href = '/login', 1000);
    } catch {
      toast.error("Failed to enable authentication");
    }
  };

  // Disable auth handler
  const handleDisableAuth = async () => {
    if (!confirm("Are you sure you want to disable authentication? This will allow anyone to access VulnForge.")) {
      return;
    }

    try {
      await settingsApi.update("user_auth_mode", "none");
      toast.success("Authentication disabled. Refreshing...");
      setTimeout(() => window.location.reload(), 1000);
    } catch {
      toast.error("Failed to disable authentication");
    }
  };

  return (
    <>
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6 break-inside-avoid">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <User className="w-6 h-6 text-blue-500" />
            <div>
              <h2 className="text-xl font-semibold text-vuln-text">User Account</h2>
              <p className="text-sm text-vuln-text-muted mt-0.5">
                {authMode === 'none' ? 'Browser authentication is disabled' :
                 authMode === 'local' ? 'Local username/password authentication' :
                 'SSO/OIDC authentication'}
              </p>
            </div>
          </div>
          <HelpTooltip content="Configure browser-based user authentication for accessing VulnForge. This is separate from API authentication used for external integrations." />
        </div>

        {/* Content - Show user profile when authenticated */}
        {user && authMode !== 'none' && (
          <div className="space-y-3">
            {/* User Profile Display */}
            <div className="flex items-center gap-3 px-4 py-3 bg-vuln-bg rounded-lg">
              <User className="w-5 h-5 text-blue-500" />
              <div className="flex-1">
                <p className="text-sm font-medium text-vuln-text">{user.username}</p>
                <p className="text-xs text-vuln-text-muted">{user.email}</p>
              </div>
              <span className="px-2 py-1 bg-blue-500/10 text-blue-500 rounded text-xs font-medium">
                {user.auth_method === 'oidc' ? `SSO (${user.oidc_provider})` : 'Local'}
              </span>
            </div>

            {/* Action Buttons - First Row */}
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => setEditProfileModalOpen(true)}
                className="px-4 py-2 bg-vuln-bg hover:bg-vuln-surface-light text-vuln-text border border-vuln-border rounded-lg font-medium transition-colors text-sm"
              >
                Edit Profile
              </button>
              {user.auth_method === 'local' && (
                <button
                  onClick={() => setChangePasswordModalOpen(true)}
                  className="px-4 py-2 bg-vuln-bg hover:bg-vuln-surface-light text-vuln-text border border-vuln-border rounded-lg font-medium transition-colors text-sm"
                >
                  Change Password
                </button>
              )}
            </div>

            {/* Action Buttons - Second Row */}
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => setOidcConfigModalOpen(true)}
                className="px-4 py-2 bg-vuln-bg hover:bg-vuln-surface-light text-vuln-text border border-vuln-border rounded-lg font-medium transition-colors text-sm flex items-center justify-center gap-2"
              >
                <Shield className="w-4 h-4" />
                OIDC/SSO
              </button>
              <button
                onClick={handleDisableAuth}
                className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/30 rounded-lg font-medium transition-colors text-sm"
              >
                Disable Auth
              </button>
            </div>
          </div>
        )}

        {/* Not Authenticated State */}
        {authMode === 'none' && (
          <div className="text-center py-4">
            <p className="text-sm text-vuln-text-muted mb-4">
              Authentication is currently disabled. Anyone can access VulnForge.
            </p>
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={handleEnableLocalAuth}
                className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-medium transition-colors text-sm"
              >
                Enable Local Auth
              </button>
              <button
                onClick={() => setOidcConfigModalOpen(true)}
                className="px-4 py-2 bg-vuln-bg hover:bg-vuln-surface-light text-vuln-text border border-vuln-border rounded-lg font-medium transition-colors text-sm flex items-center justify-center gap-2"
              >
                <Shield className="w-4 h-4" />
                Configure OIDC
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Edit Profile Modal */}
      {editProfileModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
          <div className="bg-vuln-surface border border-vuln-border rounded-lg shadow-xl max-w-md w-full p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-vuln-text">Edit Profile</h2>
              <button
                onClick={() => setEditProfileModalOpen(false)}
                className="text-vuln-text-muted hover:text-vuln-text transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Username (read-only) */}
              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  Username
                </label>
                <input
                  type="text"
                  value={user?.username || ''}
                  disabled
                  className="w-full px-4 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text-muted cursor-not-allowed"
                />
              </div>

              {/* Email */}
              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  Email
                </label>
                <input
                  type="email"
                  value={profileEmail}
                  onChange={(e) => setProfileEmail(e.target.value)}
                  className="w-full px-4 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="your@email.com"
                />
              </div>

              {/* Full Name */}
              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  Full Name
                </label>
                <input
                  type="text"
                  value={profileFullName}
                  onChange={(e) => setProfileFullName(e.target.value)}
                  className="w-full px-4 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="John Doe"
                />
              </div>

              {/* Auth Method Badge */}
              <div className="flex items-center gap-2 text-sm text-vuln-text-muted">
                <Lock className="w-4 h-4" />
                <span>Authentication: {user?.auth_method === 'oidc' ? `SSO (${user.oidc_provider})` : 'Local'}</span>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setEditProfileModalOpen(false)}
                className="flex-1 px-4 py-2 bg-vuln-bg hover:bg-vuln-surface-light text-vuln-text border border-vuln-border rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleUpdateProfile}
                disabled={savingProfile}
                className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-500/50 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
              >
                {savingProfile ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Change Password Modal */}
      {changePasswordModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
          <div className="bg-vuln-surface border border-vuln-border rounded-lg shadow-xl max-w-md w-full p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-vuln-text">Change Password</h2>
              <button
                onClick={() => setChangePasswordModalOpen(false)}
                className="text-vuln-text-muted hover:text-vuln-text transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Current Password */}
              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  Current Password
                </label>
                <div className="relative">
                  <input
                    type={showCurrentPassword ? 'text' : 'password'}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    className="w-full px-4 py-2 pr-10 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Enter current password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text"
                  >
                    {showCurrentPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* New Password */}
              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  New Password
                </label>
                <div className="relative">
                  <input
                    type={showNewPassword ? 'text' : 'password'}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full px-4 py-2 pr-10 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Enter new password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text"
                  >
                    {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Confirm Password */}
              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    type={showConfirmPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full px-4 py-2 pr-10 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Confirm new password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text"
                  >
                    {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Password Validation Display */}
              {newPassword && (
                <div className="text-xs space-y-1 mt-3">
                  <div className={`flex items-center gap-2 ${passwordValidation.length ? 'text-blue-500' : 'text-vuln-text-muted'}`}>
                    {passwordValidation.length ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                    <span>At least 8 characters</span>
                  </div>
                  <div className={`flex items-center gap-2 ${passwordValidation.uppercase ? 'text-blue-500' : 'text-vuln-text-muted'}`}>
                    {passwordValidation.uppercase ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                    <span>One uppercase letter</span>
                  </div>
                  <div className={`flex items-center gap-2 ${passwordValidation.lowercase ? 'text-blue-500' : 'text-vuln-text-muted'}`}>
                    {passwordValidation.lowercase ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                    <span>One lowercase letter</span>
                  </div>
                  <div className={`flex items-center gap-2 ${passwordValidation.number ? 'text-blue-500' : 'text-vuln-text-muted'}`}>
                    {passwordValidation.number ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                    <span>One number</span>
                  </div>
                  <div className={`flex items-center gap-2 ${passwordValidation.special ? 'text-blue-500' : 'text-vuln-text-muted'}`}>
                    {passwordValidation.special ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                    <span>One special character</span>
                  </div>
                  {confirmPassword && (
                    <div className={`flex items-center gap-2 ${passwordsMatch ? 'text-blue-500' : 'text-vuln-text-muted'}`}>
                      {passwordsMatch ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                      <span>Passwords match</span>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setChangePasswordModalOpen(false)}
                className="flex-1 px-4 py-2 bg-vuln-bg hover:bg-vuln-surface-light text-vuln-text border border-vuln-border rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleChangePassword}
                disabled={changingPassword || !currentPassword || !isPasswordValid}
                className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-500/50 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
              >
                {changingPassword ? 'Changing...' : 'Change Password'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* OIDC Configuration Modal */}
      {oidcConfigModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
          <div className="bg-vuln-surface border border-vuln-border rounded-lg shadow-xl max-w-2xl w-full p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <Shield className="w-6 h-6 text-blue-500" />
                <h2 className="text-xl font-semibold text-vuln-text">OIDC/SSO Configuration</h2>
              </div>
              <button
                onClick={() => setOidcConfigModalOpen(false)}
                className="text-vuln-text-muted hover:text-vuln-text transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-6">
              {/* Enable Toggle */}
              <div className="flex items-center justify-between">
                <div>
                  <label className="block text-sm font-medium text-vuln-text mb-1">
                    Enable OIDC/SSO
                  </label>
                  <p className="text-sm text-vuln-text-muted">
                    Allow users to log in with Single Sign-On
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setOidcEnabled(!oidcEnabled)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${oidcEnabled ? 'bg-blue-500' : 'bg-red-500'}`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${oidcEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
                </button>
              </div>

              {/* OIDC Fields (when enabled) */}
              {oidcEnabled && (
                <>
                  {/* Provider Name */}
                  <div>
                    <label className="block text-sm font-medium text-vuln-text mb-2">
                      Provider Name
                    </label>
                    <input
                      type="text"
                      value={oidcProviderName}
                      onChange={(e) => setOidcProviderName(e.target.value)}
                      placeholder="Authentik"
                      className="w-full px-3 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <p className="text-xs text-vuln-text-muted mt-1">Display name shown on login button</p>
                  </div>

                  {/* Issuer URL */}
                  <div>
                    <label className="block text-sm font-medium text-vuln-text mb-2">
                      Issuer / Discovery URL
                    </label>
                    <input
                      type="url"
                      value={oidcIssuerUrl}
                      onChange={(e) => setOidcIssuerUrl(e.target.value)}
                      placeholder="https://auth.example.com/application/o/vulnforge/"
                      className="w-full px-3 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    />
                    <p className="text-xs text-vuln-text-muted mt-1">OIDC provider's issuer URL (/.well-known/openid-configuration will be appended)</p>
                  </div>

                  {/* Client ID */}
                  <div>
                    <label className="block text-sm font-medium text-vuln-text mb-2">
                      Client ID
                    </label>
                    <input
                      type="text"
                      value={oidcClientId}
                      onChange={(e) => setOidcClientId(e.target.value)}
                      placeholder="vulnforge-client-id"
                      className="w-full px-3 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    />
                  </div>

                  {/* Client Secret */}
                  <div>
                    <label className="block text-sm font-medium text-vuln-text mb-2">
                      Client Secret
                    </label>
                    <div className="relative">
                      <input
                        type={showOidcSecret ? 'text' : 'password'}
                        value={oidcClientSecret}
                        onChange={(e) => setOidcClientSecret(e.target.value)}
                        placeholder="Enter client secret"
                        className="w-full px-3 py-2 pr-10 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                      />
                      <button
                        type="button"
                        onClick={() => setShowOidcSecret(!showOidcSecret)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-vuln-text-muted hover:text-vuln-text"
                      >
                        {showOidcSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Scopes */}
                  <div>
                    <label className="block text-sm font-medium text-vuln-text mb-2">
                      Scopes
                    </label>
                    <input
                      type="text"
                      value={oidcScopes}
                      onChange={(e) => setOidcScopes(e.target.value)}
                      placeholder="openid profile email"
                      className="w-full px-3 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    />
                    <p className="text-xs text-vuln-text-muted mt-1">Space-separated list of OIDC scopes to request</p>
                  </div>

                  {/* Username Claim */}
                  <div>
                    <label className="block text-sm font-medium text-vuln-text mb-2">
                      Username Claim
                    </label>
                    <input
                      type="text"
                      value={oidcUsernameClaim}
                      onChange={(e) => setOidcUsernameClaim(e.target.value)}
                      placeholder="preferred_username"
                      className="w-full px-3 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    />
                    <p className="text-xs text-vuln-text-muted mt-1">OIDC claim to use for username</p>
                  </div>

                  {/* Email Claim */}
                  <div>
                    <label className="block text-sm font-medium text-vuln-text mb-2">
                      Email Claim
                    </label>
                    <input
                      type="text"
                      value={oidcEmailClaim}
                      onChange={(e) => setOidcEmailClaim(e.target.value)}
                      placeholder="email"
                      className="w-full px-3 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    />
                    <p className="text-xs text-vuln-text-muted mt-1">OIDC claim to use for email address</p>
                  </div>

                  {/* Redirect URI Info */}
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 flex items-start gap-3">
                    <AlertCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="text-sm font-medium text-blue-200">OIDC Redirect URI</p>
                      <p className="text-sm text-vuln-text-muted mt-1">
                        Configure this redirect URI in your OIDC provider:
                      </p>
                      <code className="block mt-2 text-xs bg-vuln-bg px-3 py-2 rounded border border-vuln-border text-blue-300 font-mono break-all">
                        {window.location.origin}/api/v1/user-auth/oidc/callback
                      </code>
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setOidcConfigModalOpen(false)}
                className="flex-1 px-4 py-2 bg-vuln-bg hover:bg-vuln-surface-light text-vuln-text border border-vuln-border rounded-lg transition-colors"
              >
                Cancel
              </button>
              {oidcEnabled && (
                <button
                  onClick={handleTestOidcConnection}
                  disabled={testingOidc || savingOidc}
                  className="px-4 py-2 bg-vuln-bg hover:bg-vuln-surface-light text-vuln-text border border-vuln-border rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {testingOidc ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Testing...
                    </>
                  ) : (
                    <>
                      <Check className="w-4 h-4" />
                      Test Connection
                    </>
                  )}
                </button>
              )}
              <button
                onClick={handleSaveOidcConfig}
                disabled={savingOidc || testingOidc}
                className="px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-500/50 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center gap-2"
              >
                {savingOidc ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Check className="w-4 h-4" />
                    Save Configuration
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
