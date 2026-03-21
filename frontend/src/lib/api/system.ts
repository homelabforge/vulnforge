import type {
  TrivyDbInfo,
  ScannersInfoResponse,
  AppInfo,
  Setting,
  SettingUpdateResponse,
  TestConnectionResult,
} from '../../types/api/system';
import { API_BASE, handleResponse } from './client';

export const systemApi = {
  getAppInfo: async (): Promise<AppInfo> => {
    const res = await fetch(`${API_BASE}/system/info`);
    return handleResponse(res);
  },

  getTrivyDbInfo: async (): Promise<TrivyDbInfo> => {
    const res = await fetch(`${API_BASE}/system/trivy-db-info`);
    return handleResponse(res);
  },

  getScannersInfo: async (): Promise<ScannersInfoResponse> => {
    const res = await fetch(`${API_BASE}/system/scanners`);
    return handleResponse(res);
  },
};

export const settingsApi = {
  getAll: async (): Promise<Setting[]> => {
    const res = await fetch(`${API_BASE}/settings/`);
    return handleResponse(res);
  },

  getByKey: async (key: string): Promise<Setting> => {
    const res = await fetch(`${API_BASE}/settings/${key}`);
    return handleResponse(res);
  },

  update: async (key: string, value: string): Promise<SettingUpdateResponse> => {
    const res = await fetch(`${API_BASE}/settings/${key}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value }),
    });
    return handleResponse(res);
  },

  bulkUpdate: async (settings: Record<string, string>): Promise<SettingUpdateResponse[]> => {
    const res = await fetch(`${API_BASE}/settings/bulk`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ settings }),
    });
    return handleResponse(res);
  },

  testDocker: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/settings/test/docker`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  // Multi-service notification test endpoints
  testNtfy: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/ntfy`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testGotify: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/gotify`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testPushover: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/pushover`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testSlack: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/slack`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testDiscord: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/discord`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testTelegram: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/telegram`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testEmail: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/email`, {
      method: "POST",
    });
    return handleResponse(res);
  },
};
