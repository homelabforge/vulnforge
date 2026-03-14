import type {
  UserProfile,
  LoginRequest,
  TokenResponse,
  SetupRequest,
  SetupResponse,
  UpdateProfileRequest,
  ChangePasswordRequest,
  UserAuthStatusResponse,
  MessageResponse,
} from '../../types/auth';
import { API_BASE, handleResponse } from './client';

export const userAuthApi = {
  // Public endpoints (no auth required)
  getStatus: async (): Promise<UserAuthStatusResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/status`);
    return handleResponse(res);
  },

  login: async (data: LoginRequest): Promise<TokenResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  setup: async (data: SetupRequest): Promise<SetupResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  cancelSetup: async (): Promise<MessageResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/cancel-setup`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  // Protected endpoints (auth required)
  logout: async (): Promise<MessageResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/logout`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  getMe: async (): Promise<UserProfile> => {
    const res = await fetch(`${API_BASE}/user-auth/me`);
    return handleResponse(res);
  },

  updateProfile: async (data: UpdateProfileRequest): Promise<UserProfile> => {
    const res = await fetch(`${API_BASE}/user-auth/me`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  changePassword: async (data: ChangePasswordRequest): Promise<MessageResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/password`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  // OIDC test connection
  testOidcConnection: async (issuerUrl: string, clientId: string, clientSecret: string): Promise<{
    success: boolean;
    provider_reachable: boolean;
    metadata_valid: boolean;
    endpoints_found: boolean;
    errors: string[];
  }> => {
    const res = await fetch(`${API_BASE}/user-auth/oidc/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        issuer_url: issuerUrl,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    return handleResponse(res);
  },
};
