import { useState, useEffect } from "react";
import { Download, Trash2, RefreshCw, Calendar, HardDrive, RotateCcw } from "lucide-react";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { maintenanceApi, type BackupEntry } from "@/lib/api";
import { formatRelativeDate } from "@/lib/utils";

export function DatabaseBackupSection() {
  const [backups, setBackups] = useState<BackupEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);

  // Load backups on mount
  useEffect(() => {
    loadBackups();
  }, []);

  const loadBackups = async () => {
    try {
      setLoading(true);
      const data = await maintenanceApi.listBackups();
      setBackups(data.backups || []);
    } catch (error) {
      handleApiError(error, "Failed to load backups");
    } finally {
      setLoading(false);
    }
  };

  const createBackup = async () => {
    try {
      setCreating(true);
      const data = await maintenanceApi.createBackup();
      toast.success(`Backup created: ${data.filename} (${data.size_mb} MB)`);
      await loadBackups();
    } catch (error) {
      handleApiError(error, "Failed to create backup");
    } finally {
      setCreating(false);
    }
  };

  const downloadBackup = async (filename: string) => {
    try {
      const blob = await maintenanceApi.downloadBackup(filename);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      toast.success("Backup downloaded");
    } catch (error) {
      handleApiError(error, "Failed to download backup");
    }
  };

  const deleteBackup = async (filename: string) => {
    if (!confirm(`Are you sure you want to delete backup: ${filename}?`)) {
      return;
    }

    try {
      await maintenanceApi.deleteBackup(filename);
      toast.success("Backup deleted");
      await loadBackups();
    } catch (error) {
      handleApiError(error, "Failed to delete backup");
    }
  };

  const restoreBackup = async (filename: string) => {
    // Strong confirmation since this is destructive
    const confirmMessage = `⚠️ RESTORE DATABASE FROM BACKUP ⚠️

This will:
1. Replace your CURRENT database with this backup
2. You will LOSE all data added after this backup was created
3. A safety backup will be created automatically

Backup to restore: ${filename}

Type 'RESTORE' to confirm:`;

    const confirmation = prompt(confirmMessage);
    if (confirmation !== "RESTORE") {
      return;
    }

    try {
      toast.loading("Restoring database...", { id: "restore" });
      const data = await maintenanceApi.restoreBackup(filename);
      toast.success(
        `Database restored! Safety backup created: ${data.safety_backup}. Reloading...`,
        { id: "restore", duration: 5000 }
      );
      // Reload the page after a short delay
      setTimeout(() => {
        window.location.reload();
      }, 2000);
    } catch (error) {
      handleApiError(error, "Failed to restore backup");
      toast.dismiss("restore");
    }
  };

  return (
    <div className="space-y-4">
      {/* Manual Backup Button */}
      <div className="flex items-center justify-between p-4 bg-vuln-surface-light border border-vuln-border rounded-lg">
        <div>
          <h3 className="text-sm font-medium text-vuln-text">Create Manual Backup</h3>
          <p className="text-xs text-vuln-text-disabled mt-1">
            Create an instant backup of your database including all scans, settings, and secret reviews
          </p>
        </div>
        <button
          onClick={createBackup}
          disabled={creating}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-vuln-surface text-white rounded-lg flex items-center gap-2 transition-colors"
        >
          {creating ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Creating...
            </>
          ) : (
            <>
              <HardDrive className="w-4 h-4" />
              Create Backup
            </>
          )}
        </button>
      </div>

      {/* Backup List */}
      <div className="bg-vuln-surface-light border border-vuln-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-vuln-text">Available Backups ({backups.length})</h3>
          <button
            onClick={loadBackups}
            disabled={loading}
            className="text-vuln-text-muted hover:text-vuln-text transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>

        {loading ? (
          <p className="text-sm text-vuln-text-disabled text-center py-4">Loading backups...</p>
        ) : backups.length === 0 ? (
          <p className="text-sm text-vuln-text-disabled text-center py-4">No backups found. Create your first backup above.</p>
        ) : (
          <div className="space-y-2">
            {backups.map((backup) => (
              <div
                key={backup.filename}
                className="flex items-center justify-between p-3 bg-vuln-surface border border-vuln-border rounded-lg hover:border-purple-500/50 transition-colors"
              >
                <div className="flex-1">
                  <p className="text-sm font-medium text-vuln-text font-mono">{backup.filename}</p>
                  <div className="flex items-center gap-3 mt-1 text-xs text-vuln-text-disabled">
                    <span className="flex items-center gap-1">
                      <HardDrive className="w-3 h-3" />
                      {backup.size_mb} MB
                    </span>
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3 h-3" />
                      {formatRelativeDate(backup.created_at)}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => restoreBackup(backup.filename)}
                    className="p-2 text-green-400 hover:text-green-300 hover:bg-green-500/10 rounded transition-colors"
                    title="Restore from this backup"
                  >
                    <RotateCcw className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => downloadBackup(backup.filename)}
                    className="p-2 text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded transition-colors"
                    title="Download backup"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => deleteBackup(backup.filename)}
                    className="p-2 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors"
                    title="Delete backup"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Info */}
      <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-3">
        <p className="text-xs text-vuln-text-muted">
          <strong className="text-purple-400">Note:</strong> Backups are stored in{" "}
          <code className="bg-vuln-surface-light px-1 rounded">/data/backups/</code> and persist across container rebuilds.
          Download backups to keep them outside the container for extra safety.
        </p>
      </div>
    </div>
  );
}
