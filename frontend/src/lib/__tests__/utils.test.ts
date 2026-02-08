/**
 * Tests for utility functions
 */
import { describe, it, expect } from "vitest";
import { cn, formatDate, formatRelativeDate, getSeverityColor, getSeverityBadge, formatBytes } from "../utils";

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("foo", "bar")).toBe("foo bar");
  });

  it("handles conditional classes", () => {
    const isHidden = false;
    expect(cn("base", isHidden && "hidden", "visible")).toBe("base visible");
  });

  it("resolves tailwind conflicts via twMerge", () => {
    // twMerge should resolve p-4 vs p-2 to just p-2
    expect(cn("p-4", "p-2")).toBe("p-2");
  });

  it("handles empty inputs", () => {
    expect(cn()).toBe("");
  });

  it("handles undefined and null", () => {
    expect(cn("base", undefined, null, "end")).toBe("base end");
  });
});

describe("formatDate", () => {
  it("returns 'Never' for null", () => {
    expect(formatDate(null)).toBe("Never");
  });

  it("returns 'Never' for undefined", () => {
    expect(formatDate(undefined)).toBe("Never");
  });

  it("returns 'Never' for empty string", () => {
    expect(formatDate("")).toBe("Never");
  });

  it("formats a valid date string with timezone", () => {
    const result = formatDate("2025-06-15T14:30:00Z", "America/New_York");
    // Should contain the date parts
    expect(result).toContain("Jun");
    expect(result).toContain("15");
    expect(result).toContain("2025");
  });

  it("falls back gracefully for invalid timezone", () => {
    // Invalid timezone should trigger the catch and use default toLocaleString
    const result = formatDate("2025-06-15T14:30:00Z", "Invalid/Timezone");
    expect(result).toBeTruthy();
    expect(typeof result).toBe("string");
  });
});

describe("formatRelativeDate", () => {
  it("returns 'Never' for null", () => {
    expect(formatRelativeDate(null)).toBe("Never");
  });

  it("returns 'Never' for undefined", () => {
    expect(formatRelativeDate(undefined)).toBe("Never");
  });

  it("returns 'Just now' for very recent dates", () => {
    const now = new Date().toISOString();
    expect(formatRelativeDate(now)).toBe("Just now");
  });

  it("returns minutes ago for recent dates", () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    expect(formatRelativeDate(fiveMinAgo)).toBe("5m ago");
  });

  it("returns hours ago for older dates", () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    expect(formatRelativeDate(twoHoursAgo)).toBe("2h ago");
  });

  it("returns days ago for old dates", () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
    expect(formatRelativeDate(threeDaysAgo)).toBe("3d ago");
  });
});

describe("getSeverityColor", () => {
  it("returns red classes for CRITICAL", () => {
    const result = getSeverityColor("CRITICAL");
    expect(result).toContain("text-red-500");
    expect(result).toContain("bg-red-500/10");
  });

  it("returns orange classes for HIGH", () => {
    const result = getSeverityColor("HIGH");
    expect(result).toContain("text-orange-500");
  });

  it("returns yellow classes for MEDIUM", () => {
    const result = getSeverityColor("MEDIUM");
    expect(result).toContain("text-yellow-500");
  });

  it("returns green classes for LOW", () => {
    const result = getSeverityColor("LOW");
    expect(result).toContain("text-green-500");
  });

  it("returns gray classes for unknown severity", () => {
    const result = getSeverityColor("UNKNOWN");
    expect(result).toContain("text-gray-500");
  });

  it("is case-insensitive", () => {
    expect(getSeverityColor("critical")).toContain("text-red-500");
    expect(getSeverityColor("Critical")).toContain("text-red-500");
  });
});

describe("getSeverityBadge", () => {
  it("includes base badge classes", () => {
    const result = getSeverityBadge("HIGH");
    expect(result).toContain("px-2");
    expect(result).toContain("py-1");
    expect(result).toContain("rounded");
    expect(result).toContain("font-semibold");
  });

  it("includes severity-specific colors", () => {
    const result = getSeverityBadge("CRITICAL");
    expect(result).toContain("text-red-500");
  });
});

describe("formatBytes", () => {
  it("returns 'N/A' for null", () => {
    expect(formatBytes(null)).toBe("N/A");
  });

  it("returns '0 B' for zero", () => {
    expect(formatBytes(0)).toBe("0 B");
  });

  it("formats bytes", () => {
    expect(formatBytes(500)).toBe("500.0 B");
  });

  it("formats kilobytes", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
  });

  it("formats megabytes", () => {
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
  });

  it("formats gigabytes", () => {
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.0 GB");
  });

  it("formats terabytes", () => {
    expect(formatBytes(1024 * 1024 * 1024 * 1024)).toBe("1.0 TB");
  });

  it("formats fractional values", () => {
    expect(formatBytes(1536)).toBe("1.5 KB");
  });
});
