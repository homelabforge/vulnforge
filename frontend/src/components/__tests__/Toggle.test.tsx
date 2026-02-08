/**
 * Tests for Toggle component
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Toggle } from "../Toggle";

describe("Toggle", () => {
  it("renders a checkbox input", () => {
    render(<Toggle checked={false} onChange={() => {}} />);
    const input = screen.getByRole("switch");
    expect(input).toBeInTheDocument();
    expect(input.tagName).toBe("INPUT");
  });

  it("reflects checked state", () => {
    render(<Toggle checked={true} onChange={() => {}} />);
    const input = screen.getByRole("switch");
    expect(input).toBeChecked();
  });

  it("reflects unchecked state", () => {
    render(<Toggle checked={false} onChange={() => {}} />);
    const input = screen.getByRole("switch");
    expect(input).not.toBeChecked();
  });

  it("calls onChange when clicked", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} />);

    await user.click(screen.getByRole("switch"));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("calls onChange with false when unchecking", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Toggle checked={true} onChange={onChange} />);

    await user.click(screen.getByRole("switch"));
    expect(onChange).toHaveBeenCalledWith(false);
  });

  it("has role='switch'", () => {
    render(<Toggle checked={false} onChange={() => {}} />);
    expect(screen.getByRole("switch")).toBeDefined();
  });

  it("has aria-checked matching checked prop", () => {
    const { rerender } = render(<Toggle checked={false} onChange={() => {}} />);
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "false");

    rerender(<Toggle checked={true} onChange={() => {}} />);
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "true");
  });

  it("can be disabled", () => {
    render(<Toggle checked={false} onChange={() => {}} disabled />);
    expect(screen.getByRole("switch")).toBeDisabled();
  });

  it("does not call onChange when disabled", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} disabled />);

    await user.click(screen.getByRole("switch"));
    expect(onChange).not.toHaveBeenCalled();
  });
});
