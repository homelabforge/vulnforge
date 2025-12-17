/**
 * Utility functions for VulnForge
 */

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format a date string for display using the specified timezone.
 * If no timezone is provided, uses the browser's local timezone.
 */
export function formatDate(
  dateString: string | null | undefined,
  timezone?: string
): string {
  if (!dateString) return "Never";
  const date = new Date(dateString);

  try {
    return date.toLocaleString('en-US', {
      timeZone: timezone || Intl.DateTimeFormat().resolvedOptions().timeZone,
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    // Fallback if timezone is invalid
    return date.toLocaleString();
  }
}

/**
 * Format a date as relative time (e.g., "5m ago", "2h ago").
 * Uses the specified timezone for accurate comparison.
 */
export function formatRelativeDate(
  dateString: string | null | undefined,
  timezone?: string
): string {
  if (!dateString) return "Never";
  const date = new Date(dateString);

  // Get current time in the specified timezone for accurate comparison
  let now: Date;
  if (timezone) {
    try {
      // Create a date string in the target timezone, then parse it
      const nowStr = new Date().toLocaleString('en-US', { timeZone: timezone });
      now = new Date(nowStr);
    } catch {
      now = new Date();
    }
  } else {
    now = new Date();
  }

  const diff = now.getTime() - date.getTime();

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return "Just now";
}

export function getSeverityColor(severity: string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "text-red-500 bg-red-500/10 border-red-500/20";
    case "HIGH":
      return "text-orange-500 bg-orange-500/10 border-orange-500/20";
    case "MEDIUM":
      return "text-yellow-500 bg-yellow-500/10 border-yellow-500/20";
    case "LOW":
      return "text-green-500 bg-green-500/10 border-green-500/20";
    default:
      return "text-gray-500 bg-gray-500/10 border-gray-500/20";
  }
}

export function getSeverityBadge(severity: string): string {
  const base = "px-2 py-1 rounded text-xs font-semibold border";
  return cn(base, getSeverityColor(severity));
}

export function formatBytes(bytes: number | null): string {
  if (bytes === null || bytes === undefined) return "N/A";
  if (bytes === 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }

  return `${size.toFixed(1)} ${units[unitIndex]}`;
}
