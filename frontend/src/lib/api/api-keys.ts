import type { APIKey, APIKeyCreate, APIKeyCreated, APIKeyList } from '../../types/api/system';
import { API_BASE, handleResponse } from './client';

export const apiKeysApi = {
  list: async (includeRevoked: boolean = false): Promise<APIKeyList> => {
    const res = await fetch(`${API_BASE}/api-keys?include_revoked=${includeRevoked}`);
    return handleResponse(res);
  },

  create: async (data: APIKeyCreate): Promise<APIKeyCreated> => {
    const res = await fetch(`${API_BASE}/api-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  get: async (id: number): Promise<APIKey> => {
    const res = await fetch(`${API_BASE}/api-keys/${id}`);
    return handleResponse(res);
  },

  revoke: async (id: number): Promise<APIKey> => {
    const res = await fetch(`${API_BASE}/api-keys/${id}`, {
      method: "DELETE",
    });
    return handleResponse(res);
  },
};
