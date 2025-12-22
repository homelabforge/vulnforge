/**
 * Authentication types for VulnForge user auth
 */

export interface UserProfile {
  username: string;
  email: string;
  full_name: string | null;
  auth_method: "local" | "oidc";
  oidc_provider: string | null;
  created_at: string | null;
  last_login: string | null;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  csrf_token?: string;
}

export interface SetupRequest {
  username: string;
  email: string;
  password: string;
  full_name?: string;
}

export interface SetupResponse {
  username: string;
  email: string;
  full_name: string | null;
  message: string;
}

export interface UpdateProfileRequest {
  email?: string;
  full_name?: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface UserAuthStatusResponse {
  setup_complete: boolean;
  auth_mode: "none" | "local" | "oidc";
  oidc_enabled: boolean;
}

export interface MessageResponse {
  message: string;
}
