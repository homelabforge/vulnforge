/**
 * Tests for useSettingsForm hook
 *
 * Covers: field initialization from settingsMap, bool/string handling,
 * truthy/falsy defaults, auto-save integration, update methods
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useSettingsForm, type SettingsFieldDef } from "../useSettingsForm";

const FIELDS: SettingsFieldDef[] = [
  { key: "enabled", type: "bool", defaultValue: true },
  { key: "name", type: "string", defaultValue: "default" },
  { key: "opt_in", type: "bool", defaultValue: false, boolDefault: "falsy" },
  { key: "opt_out", type: "bool", defaultValue: true, boolDefault: "truthy" },
];

describe("useSettingsForm", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("initializes values from settingsMap", () => {
    const onSave = vi.fn();
    const settingsMap = { enabled: "true", name: "custom", opt_in: "true", opt_out: "false" };

    const { result } = renderHook(() =>
      useSettingsForm(settingsMap, FIELDS, onSave),
    );

    expect(result.current.values.enabled).toBe(true);
    expect(result.current.values.name).toBe("custom");
    expect(result.current.values.opt_in).toBe(true);
    expect(result.current.values.opt_out).toBe(false);
  });

  it("uses defaults when settingsMap is empty", () => {
    const onSave = vi.fn();
    const settingsMap: Record<string, string> = {};

    const { result } = renderHook(() =>
      useSettingsForm(settingsMap, FIELDS, onSave),
    );

    expect(result.current.values.enabled).toBe(true); // default
    expect(result.current.values.name).toBe("default");
    expect(result.current.values.opt_in).toBe(false); // falsy default
    expect(result.current.values.opt_out).toBe(true); // truthy default
  });

  it("handles truthy bool default (true unless explicitly 'false')", () => {
    const onSave = vi.fn();

    // "true" string → true, "false" string → false, missing → default
    const { result: r1 } = renderHook(() =>
      useSettingsForm({ opt_out: "false" }, FIELDS, onSave),
    );
    expect(r1.current.values.opt_out).toBe(false);

    const { result: r2 } = renderHook(() =>
      useSettingsForm({ opt_out: "true" }, FIELDS, onSave),
    );
    expect(r2.current.values.opt_out).toBe(true);
  });

  it("handles falsy bool default (false unless explicitly 'true')", () => {
    const onSave = vi.fn();

    const { result: r1 } = renderHook(() =>
      useSettingsForm({ opt_in: "true" }, FIELDS, onSave),
    );
    expect(r1.current.values.opt_in).toBe(true);

    const { result: r2 } = renderHook(() =>
      useSettingsForm({ opt_in: "false" }, FIELDS, onSave),
    );
    expect(r2.current.values.opt_in).toBe(false);
  });

  it("setBool updates a boolean field and triggers auto-save", () => {
    const onSave = vi.fn();
    const { result } = renderHook(() =>
      useSettingsForm({ enabled: "true", name: "test" }, FIELDS, onSave),
    );

    act(() => {
      result.current.setBool("enabled", false);
    });

    expect(result.current.values.enabled).toBe(false);

    vi.advanceTimersByTime(800);
    expect(onSave).toHaveBeenCalledOnce();
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ enabled: "false" }),
    );
  });

  it("setText updates a string field and triggers auto-save", () => {
    const onSave = vi.fn();
    const { result } = renderHook(() =>
      useSettingsForm({ name: "old" }, FIELDS, onSave),
    );

    act(() => {
      result.current.setText("name", "new");
    });

    expect(result.current.values.name).toBe("new");

    vi.advanceTimersByTime(800);
    expect(onSave).toHaveBeenCalledOnce();
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ name: "new" }),
    );
  });

  it("serializes booleans to strings in save payload", () => {
    const onSave = vi.fn();
    const { result } = renderHook(() =>
      useSettingsForm({ enabled: "true" }, FIELDS, onSave),
    );

    act(() => {
      result.current.setBool("enabled", false);
    });

    vi.advanceTimersByTime(800);
    const payload = onSave.mock.calls[0][0];
    expect(typeof payload.enabled).toBe("string");
    expect(payload.enabled).toBe("false");
  });
});
