import type { BackupEntry } from '../../types/api/maintenance';
import { API_BASE, handleResponse, handleBlobResponse } from './client';

export const maintenanceApi = {
  listBackups: async (): Promise<{ backups: BackupEntry[] }> => {
    const res = await fetch(`${API_BASE}/maintenance/backup/list`);
    return handleResponse(res);
  },

  createBackup: async (): Promise<{ filename: string; size_mb: number }> => {
    const res = await fetch(`${API_BASE}/maintenance/backup`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  downloadBackup: async (filename: string): Promise<Blob> => {
    const res = await fetch(`${API_BASE}/maintenance/backup/download/${filename}`);
    return handleBlobResponse(res);
  },

  deleteBackup: async (filename: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/maintenance/backup/${filename}`, {
      method: "DELETE",
    });
    return handleResponse(res);
  },

  restoreBackup: async (filename: string): Promise<{ safety_backup: string }> => {
    const res = await fetch(`${API_BASE}/maintenance/backup/restore/${filename}`, {
      method: "POST",
    });
    return handleResponse(res);
  },
};
