/**
 * React Query hooks for VulnForge API
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useRef, useEffect } from "react";
import {
  activityApi,
  containersApi,
  scansApi,
  vulnerabilitiesApi,
  secretsApi,
  widgetApi,
  settingsApi,
  systemApi,
} from "@/lib/api";

// Containers hooks
export function useContainers() {
  return useQuery({
    queryKey: ["containers"],
    queryFn: () => containersApi.getAll(),
    refetchInterval: 30000, // Refetch every 30s
  });
}

export function useContainer(id: number) {
  return useQuery({
    queryKey: ["container", id],
    queryFn: () => containersApi.getById(id),
    enabled: !!id,
  });
}

export function useDiscoverContainers() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => containersApi.discover(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["containers"] });
    },
  });
}

// Scans hooks
export function useTriggerScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (containerIds?: number[]) => scansApi.trigger(containerIds),
    onSuccess: async () => {
      // Force immediate refetch to ensure UI updates instantly (no waiting for polling cycle)
      await queryClient.refetchQueries({ queryKey: ["scanStatus"] });
      queryClient.invalidateQueries({ queryKey: ["containers"] });
    },
  });
}

export function useScanStatus() {
  const queryClient = useQueryClient();
  const previousStatusRef = useRef<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const query = useQuery({
    queryKey: ["scanStatus"],
    queryFn: () => scansApi.getCurrent(),
    staleTime: Infinity,
    refetchInterval: false,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    let retryHandle: number | undefined;
    let closed = false;

    const connect = () => {
      if (closed) return;

      const source = new EventSource("/api/v1/scans/stream");
      eventSourceRef.current = source;

      const handleMessage = (event: MessageEvent) => {
        try {
          const payload = JSON.parse(event.data);
          queryClient.setQueryData(["scanStatus"], payload);
        } catch (error) {
          console.error("Failed to parse scan status event", error);
        }
      };

      const scheduleReconnect = () => {
        source.removeEventListener("scan-status", handleMessage as EventListener);
        source.onerror = null;
        source.close();
        eventSourceRef.current = null;
        if (closed) return;
        if (retryHandle) window.clearTimeout(retryHandle);
        retryHandle = window.setTimeout(connect, 3000);
      };

      source.addEventListener("scan-status", handleMessage as EventListener);
      source.onerror = scheduleReconnect;
    };

    connect();

    return () => {
      closed = true;
      if (retryHandle) window.clearTimeout(retryHandle);
      const source = eventSourceRef.current;
      if (source) {
        source.close();
        eventSourceRef.current = null;
      }
    };
  }, [queryClient]);

  // Watch for scan completion and invalidate data queries
  useEffect(() => {
    if (query.data) {
      const currentStatus = query.data.status;
      const previousStatus = previousStatusRef.current;

      // If scan just completed (transition from scanning to idle)
      if (previousStatus === "scanning" && currentStatus === "idle") {
        // Invalidate all data-related queries so they refetch with new scan results
        queryClient.invalidateQueries({ queryKey: ["widgetSummary"] });
        queryClient.invalidateQueries({ queryKey: ["containers"] });
        queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
        queryClient.invalidateQueries({ queryKey: ["remediationGroups"] });
        queryClient.invalidateQueries({ queryKey: ["scanTrends"] });
      }

      previousStatusRef.current = currentStatus;
    }
  }, [query.data, queryClient]);

  return query;
}

export function useScanHistory(containerId: number) {
  return useQuery({
    queryKey: ["scanHistory", containerId],
    queryFn: () => scansApi.getHistory(containerId),
    enabled: !!containerId,
  });
}

export function useScanTrends(windowDays = 30) {
  return useQuery({
    queryKey: ["scanTrends", windowDays],
    queryFn: () => scansApi.getTrends(windowDays),
    refetchInterval: 5 * 60 * 1000,
  });
}

// Vulnerabilities hooks
export function useVulnerabilities(params?: {
  severity?: string;
  fixable_only?: boolean;
  kev_only?: boolean;
  status?: string;
  container_id?: number;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["vulnerabilities", params],
    queryFn: () => vulnerabilitiesApi.getAll(params),
  });
}

export function useVulnerability(id: number) {
  return useQuery({
    queryKey: ["vulnerability", id],
    queryFn: () => vulnerabilitiesApi.getById(id),
    enabled: !!id,
  });
}

export function useUpdateVulnerability() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, notes }: { id: number; status: string; notes?: string }) =>
      vulnerabilitiesApi.updateStatus(id, status, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
      queryClient.invalidateQueries({ queryKey: ["widgetSummary"] });
    },
  });
}

export function useBulkUpdateVulnerabilities() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ ids, status, notes }: { ids: number[]; status: string; notes?: string }) =>
      vulnerabilitiesApi.bulkUpdate(ids, status, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
      queryClient.invalidateQueries({ queryKey: ["widgetSummary"] });
    },
  });
}

export function useRemediationGroups(containerId?: number) {
  return useQuery({
    queryKey: ["remediationGroups", containerId],
    queryFn: () => vulnerabilitiesApi.getRemediationGroups(containerId),
  });
}

// Widget hooks
export function useWidgetSummary() {
  return useQuery({
    queryKey: ["widgetSummary"],
    queryFn: () => widgetApi.getSummary(),
    refetchInterval: 30000, // Refetch every 30s
  });
}

// Settings hooks
export function useSettings() {
  return useQuery({
    queryKey: ["settings"],
    queryFn: () => settingsApi.getAll(),
  });
}

export function useUpdateSetting() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ key, value }: { key: string; value: string }) =>
      settingsApi.update(key, value),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });
}

export function useBulkUpdateSettings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (settings: Record<string, string>) => settingsApi.bulkUpdate(settings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });
}

export function useTestDockerConnection() {
  return useMutation({
    mutationFn: () => settingsApi.testDocker(),
  });
}

// Secrets hooks
export function useContainerSecrets(containerId: number) {
  return useQuery({
    queryKey: ["secrets", "container", containerId],
    queryFn: () => secretsApi.getContainerSecrets(containerId),
    enabled: !!containerId,
  });
}

export function useScanSecrets(scanId: number) {
  return useQuery({
    queryKey: ["secrets", "scan", scanId],
    queryFn: () => secretsApi.getScanSecrets(scanId),
    enabled: !!scanId,
  });
}

export function useSecretsSummary() {
  return useQuery({
    queryKey: ["secrets", "summary"],
    queryFn: () => secretsApi.getSummary(),
    refetchInterval: 30000, // Refetch every 30s
  });
}

export function useAllSecrets(filters?: {
  severity?: string;
  category?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["secrets", "all", filters],
    queryFn: () => secretsApi.getAll(filters),
  });
}

export function useUpdateSecret() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, notes }: { id: number; status: string; notes?: string }) =>
      secretsApi.updateStatus(id, status, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] });
      queryClient.invalidateQueries({ queryKey: ["widgetSummary"] });
      queryClient.invalidateQueries({ queryKey: ["containers"] });
    },
  });
}

export function useBulkUpdateSecrets() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ ids, status, notes }: { ids: number[]; status: string; notes?: string }) =>
      secretsApi.bulkUpdate(ids, status, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] });
      queryClient.invalidateQueries({ queryKey: ["widgetSummary"] });
      queryClient.invalidateQueries({ queryKey: ["containers"] });
    },
  });
}

// System hooks
export function useTrivyDbInfo() {
  return useQuery({
    queryKey: ["trivyDbInfo"],
    queryFn: systemApi.getTrivyDbInfo,
    refetchInterval: 60000, // Refetch every 60 seconds
  });
}

// Activity hooks
export function useActivities(params?: {
  limit?: number;
  offset?: number;
  event_type?: string;
  severity?: string;
  container_id?: number;
}) {
  return useQuery({
    queryKey: ["activities", params],
    queryFn: () => activityApi.getRecent(params),
    refetchInterval: 15000, // Auto-refresh every 15 seconds
  });
}

export function useActivityTypes() {
  return useQuery({
    queryKey: ["activityTypes"],
    queryFn: activityApi.getTypes,
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useContainerActivities(containerId: number, limit?: number) {
  return useQuery({
    queryKey: ["containerActivities", containerId, limit],
    queryFn: () => activityApi.getByContainer(containerId, limit),
    refetchInterval: 15000, // Auto-refresh every 15 seconds
  });
}
