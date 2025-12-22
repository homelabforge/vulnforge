import { useState, useEffect } from "react";
import { Key, Plus, Trash2, Copy, Check, AlertCircle } from "lucide-react";
import { apiKeysApi, APIKey, APIKeyCreated } from "../lib/api";
import { HelpTooltip } from "./HelpTooltip";

export function ApiKeysCard() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyDescription, setNewKeyDescription] = useState("");
  const [createdKey, setCreatedKey] = useState<APIKeyCreated | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [creating, setCreating] = useState(false);

  // Load API keys on mount
  useEffect(() => {
    loadKeys();
  }, []);

  const loadKeys = async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await apiKeysApi.list(false); // Don't include revoked keys
      setKeys(result.keys);
    } catch (err: unknown) {
      const error = err as { detail?: string };
      setError(error.detail || "Failed to load API keys");
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!newKeyName.trim()) {
      setError("Name is required");
      return;
    }

    try {
      setCreating(true);
      setError(null);
      const result = await apiKeysApi.create({
        name: newKeyName.trim(),
        description: newKeyDescription.trim() || undefined,
      });
      setCreatedKey(result);
      setNewKeyName("");
      setNewKeyDescription("");
      setShowCreateModal(false); // Close create modal after successful creation
      // Reload keys list
      await loadKeys();
    } catch (err: unknown) {
      const error = err as { detail?: string };
      setError(error.detail || "Failed to create API key");
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (id: number, name: string) => {
    if (!confirm(`Revoke API key "${name}"? This cannot be undone.`)) {
      return;
    }

    try {
      setError(null);
      await apiKeysApi.revoke(id);
      // Reload keys list
      await loadKeys();
    } catch (err: unknown) {
      const error = err as { detail?: string };
      setError(error.detail || "Failed to revoke API key");
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    } catch {
      alert("Failed to copy to clipboard");
    }
  };

  const closeCreatedModal = () => {
    setCreatedKey(null);
    setCopiedKey(false);
  };

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <Key className="w-6 h-6 text-purple-500" />
          <div>
            <h2 className="text-xl font-semibold text-vuln-text">API Keys</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">
              Manage API keys for external access (TideWatch, scripts, automation)
            </p>
          </div>
        </div>
        <HelpTooltip content="API keys provide secure access to VulnForge's API for external tools and automation. Each key is shown only once when created. Store keys securely and revoke immediately if compromised." />
      </div>

      {/* Error Alert */}
      {error && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-500/30 rounded-lg flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Create Button */}
      <div className="mb-4">
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          Create New Key
        </button>
      </div>

      {/* Keys List */}
      {loading ? (
        <div className="text-center py-8 text-vuln-text-muted">Loading...</div>
      ) : keys.length === 0 ? (
        <div className="text-center py-8 text-vuln-text-muted">
          No API keys yet. Create one to get started.
        </div>
      ) : (
        <div className="space-y-3">
          {keys.map((key) => (
            <div
              key={key.id}
              className="bg-vuln-surface-light border border-vuln-border rounded-lg p-4 flex items-center justify-between"
            >
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-vuln-text">{key.name}</span>
                  <code className="text-xs text-vuln-text-disabled bg-vuln-surface px-2 py-0.5 rounded">
                    {key.key_prefix}...
                  </code>
                </div>
                {key.description && (
                  <p className="text-sm text-vuln-text-muted mt-1">{key.description}</p>
                )}
                <div className="flex items-center gap-4 mt-2 text-xs text-vuln-text-disabled">
                  <span>Created: {new Date(key.created_at).toLocaleDateString()}</span>
                  {key.last_used_at && (
                    <span>Last used: {new Date(key.last_used_at).toLocaleString()}</span>
                  )}
                </div>
              </div>
              <button
                onClick={() => handleRevoke(key.id, key.name)}
                className="ml-4 p-2 text-red-400 hover:bg-red-900/20 rounded-lg transition-colors"
                title="Revoke key"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-vuln-text mb-4">Create New API Key</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  Name <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="TideWatch Production"
                  className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  Description (optional)
                </label>
                <textarea
                  value={newKeyDescription}
                  onChange={(e) => setNewKeyDescription(e.target.value)}
                  placeholder="API key for TideWatch monitoring service"
                  rows={3}
                  className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setNewKeyName("");
                  setNewKeyDescription("");
                  setError(null);
                }}
                className="flex-1 px-4 py-2 bg-vuln-surface-light border border-vuln-border text-vuln-text rounded-lg hover:bg-vuln-surface transition-colors"
                disabled={creating}
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={creating || !newKeyName.trim()}
                className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {creating ? "Creating..." : "Create Key"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Created Key Modal */}
      {createdKey && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6 max-w-lg w-full mx-4">
            <h3 className="text-lg font-semibold text-vuln-text mb-2">API Key Created!</h3>
            <div className="mb-4 p-3 bg-amber-900/20 border border-amber-500/30 rounded-lg flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-amber-400">{createdKey.warning}</p>
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-vuln-text mb-2">
                Your API Key
              </label>
              <div className="flex gap-2">
                <code className="flex-1 px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-sm font-mono text-vuln-text break-all">
                  {createdKey.key}
                </code>
                <button
                  onClick={() => copyToClipboard(createdKey.key)}
                  className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors flex items-center gap-2"
                >
                  {copiedKey ? (
                    <>
                      <Check className="w-4 h-4" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4" />
                      Copy
                    </>
                  )}
                </button>
              </div>
            </div>

            <div className="bg-vuln-surface-light/20 border border-vuln-border rounded-lg p-3 mb-4 text-sm text-vuln-text-muted space-y-1">
              <p><strong>Name:</strong> {createdKey.name}</p>
              {createdKey.description && <p><strong>Description:</strong> {createdKey.description}</p>}
              <p><strong>Created:</strong> {new Date(createdKey.created_at).toLocaleString()}</p>
            </div>

            <button
              onClick={closeCreatedModal}
              className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
