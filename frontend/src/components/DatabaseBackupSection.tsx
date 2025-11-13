import { useState, useEffect } from "react";
import { Download, Trash2, RefreshCw, Calendar, HardDrive, RotateCcw } from "lucide-react";
import { toast } from "sonner";

// Simple relative time formatter
const formatRelativeTime = (dateString: string): string => {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? "s" : ""} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
  return date.toLocaleDateString();
};

interface Backup {
  filename: string;
  path: string;
  size_bytes: number;
  size_mb: number;
  created_at: string;
}

export function DatabaseBackupSection() {
  const [backups, setBackups] = useState<Backup[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);

  // Load backups on mount
  useEffect(() => {
    loadBackups();
  }, []);

  const loadBackups = async () => {
    try {
      setLoading(true);
      const response = await fetch("/api/v1/maintenance/backup/list");
      if (response.ok) {
        const data = await response.json();
        setBackups(data.backups || []);
      }
    } catch (error) {
      console.error("Failed to load backups:", error);
    } finally {
      setLoading(false);
    }
  };

  const createBackup = async () => {
    try {
      setCreating(true);
      const response = await fetch("/api/v1/maintenance/backup", {
        method: "POST",
      });

      if (response.ok) {
        const data = await response.json();
        toast.success(`Backup created: ${data.filename} (${data.size_mb} MB)`);
        await loadBackups(); // Reload the list
      } else {
        const error = await response.json();
        toast.error(`Backup failed: ${error.detail}`);
      }
    } catch (error) {
      console.error("Failed to create backup", error);
      toast.error("Failed to create backup");
    } finally {
      setCreating(false);
    }
  };

  const downloadBackup = async (filename: string) => {
    try {
      const response = await fetch(`/api/v1/maintenance/backup/download/${filename}`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        toast.success("Backup downloaded");
      } else {
        toast.error("Download failed");
      }
    } catch (error) {
      console.error("Failed to download backup", error);
      toast.error("Failed to download backup");
    }
  };

  const deleteBackup = async (filename: string) => {
    if (!confirm(`Are you sure you want to delete backup: ${filename}?`)) {
      return;
    }

    try {
      const response = await fetch(`/api/v1/maintenance/backup/${filename}`, {
        method: "DELETE",
      });

      if (response.ok) {
        toast.success("Backup deleted");
        await loadBackups(); // Reload the list
      } else {
        const error = await response.json();
        toast.error(`Delete failed: ${error.detail}`);
      }
    } catch (error) {
      console.error("Failed to delete backup", error);
      toast.error("Failed to delete backup");
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
      const response = await fetch(`/api/v1/maintenance/backup/restore/${filename}`, {
        method: "POST",
      });

      if (response.ok) {
        const data = await response.json();
        toast.success(
          `Database restored! Safety backup created: ${data.safety_backup}. Reloading...`,
          { id: "restore", duration: 5000 }
        );
        // Reload the page after a short delay
        setTimeout(() => {
          window.location.reload();
        }, 2000);
      } else {
        const error = await response.json();
        toast.error(`Restore failed: ${error.detail}`, { id: "restore" });
      }
    } catch (error) {
      console.error("Failed to restore backup", error);
      toast.error("Failed to restore backup", { id: "restore" });
    }
  };

  return (
    <div className="space-y-4">
      {/* Manual Backup Button */}
      <div className="flex items-center justify-between p-4 bg-[#0f1419] border border-gray-700 rounded-lg">
        <div>
          <h3 className="text-sm font-medium text-white">Create Manual Backup</h3>
          <p className="text-xs text-gray-500 mt-1">
            Create an instant backup of your database including all scans, settings, and secret reviews
          </p>
        </div>
        <button
          onClick={createBackup}
          disabled={creating}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 text-white rounded-lg flex items-center gap-2 transition-colors"
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
      <div className="bg-[#0f1419] border border-gray-700 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-white">Available Backups ({backups.length})</h3>
          <button
            onClick={loadBackups}
            disabled={loading}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>

        {loading ? (
          <p className="text-sm text-gray-500 text-center py-4">Loading backups...</p>
        ) : backups.length === 0 ? (
          <p className="text-sm text-gray-500 text-center py-4">No backups found. Create your first backup above.</p>
        ) : (
          <div className="space-y-2">
            {backups.map((backup) => (
              <div
                key={backup.filename}
                className="flex items-center justify-between p-3 bg-[#1a1f2e] border border-gray-800 rounded-lg hover:border-purple-500/50 transition-colors"
              >
                <div className="flex-1">
                  <p className="text-sm font-medium text-white font-mono">{backup.filename}</p>
                  <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
                    <span className="flex items-center gap-1">
                      <HardDrive className="w-3 h-3" />
                      {backup.size_mb} MB
                    </span>
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3 h-3" />
                      {formatRelativeTime(backup.created_at)}
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
        <p className="text-xs text-gray-400">
          <strong className="text-purple-400">Note:</strong> Backups are stored in{" "}
          <code className="bg-[#0f1419] px-1 rounded">/data/backups/</code> and persist across container rebuilds.
          Download backups to keep them outside the container for extra safety.
        </p>
      </div>
    </div>
  );
}
