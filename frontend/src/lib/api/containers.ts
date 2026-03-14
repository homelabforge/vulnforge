import type { Container } from '../../types/api/containers';
import { API_BASE, handleResponse } from './client';

export const containersApi = {
  getAll: async (): Promise<{ containers: Container[]; total: number }> => {
    const res = await fetch(`${API_BASE}/containers/`);
    return handleResponse(res);
  },

  getById: async (id: number): Promise<Container> => {
    const res = await fetch(`${API_BASE}/containers/${id}`);
    return handleResponse(res);
  },

  discover: async (): Promise<{ total: number; discovered: string[] }> => {
    const res = await fetch(`${API_BASE}/containers/discover`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  update: async (id: number, updates: { is_my_project?: boolean; is_running?: boolean }): Promise<Container> => {
    const res = await fetch(`${API_BASE}/containers/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updates),
    });
    return handleResponse(res);
  },
};
