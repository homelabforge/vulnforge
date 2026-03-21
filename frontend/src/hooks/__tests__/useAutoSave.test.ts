/**
 * Tests for useAutoSave hook
 *
 * Covers: initialization guard, debounced save, payload diffing, stale closure handling
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { useAutoSave } from "../useAutoSave";

describe("useAutoSave", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not save on initial render (initialization guard)", () => {
    const onSave = vi.fn();
    renderHook(() =>
      useAutoSave(() => ({ key: "value" }), onSave, ["value"], true),
    );

    vi.advanceTimersByTime(1000);
    expect(onSave).not.toHaveBeenCalled();
  });

  it("saves after dependency change with 800ms debounce", () => {
    const onSave = vi.fn();
    let value = "initial";

    const { rerender } = renderHook(() =>
      useAutoSave(() => ({ key: value }), onSave, [value], true),
    );

    // Change dependency
    value = "changed";
    rerender();

    // Should not save immediately
    expect(onSave).not.toHaveBeenCalled();

    // Should save after 800ms debounce
    vi.advanceTimersByTime(800);
    expect(onSave).toHaveBeenCalledOnce();
    expect(onSave).toHaveBeenCalledWith({ key: "changed" });
  });

  it("does not save if payload is unchanged (diffing)", () => {
    const onSave = vi.fn();
    let dep = 1;

    const { rerender } = renderHook(() =>
      useAutoSave(() => ({ key: "same" }), onSave, [dep], true),
    );

    // Change dependency but payload stays the same
    dep = 2;
    rerender();

    vi.advanceTimersByTime(800);
    expect(onSave).not.toHaveBeenCalled();
  });

  it("does not save when disabled", () => {
    const onSave = vi.fn();
    let value = "initial";

    const { rerender } = renderHook(() =>
      useAutoSave(() => ({ key: value }), onSave, [value], false),
    );

    value = "changed";
    rerender();

    vi.advanceTimersByTime(800);
    expect(onSave).not.toHaveBeenCalled();
  });

  it("debounces rapid changes (only saves final value)", () => {
    const onSave = vi.fn();
    let value = "initial";

    const { rerender } = renderHook(() =>
      useAutoSave(() => ({ key: value }), onSave, [value], true),
    );

    // Rapid changes within debounce window
    value = "change1";
    rerender();
    vi.advanceTimersByTime(200);

    value = "change2";
    rerender();
    vi.advanceTimersByTime(200);

    value = "change3";
    rerender();
    vi.advanceTimersByTime(800);

    expect(onSave).toHaveBeenCalledOnce();
    expect(onSave).toHaveBeenCalledWith({ key: "change3" });
  });
});
