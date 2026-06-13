import { afterEach, describe, expect, it, vi } from "vitest";
import { createElement } from "react";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { useDebouncedCallback, type DebouncedCallback } from "./use-debounced-callback";

// A tiny harness: render a component that exposes the debounced callback so the
// test can drive it, then unmount to assert flush-on-unmount behaviour.

let root: Root | null = null;
let container: HTMLElement | null = null;

function mount(ui: React.ReactElement) {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  act(() => {
    root!.render(ui);
  });
}

function unmount() {
  act(() => {
    root?.unmount();
  });
  container?.remove();
  root = null;
  container = null;
}

afterEach(() => {
  unmount();
  vi.useRealTimers();
});

function Harness({
  fn,
  delay,
  onReady,
}: {
  fn: (v: string) => void;
  delay: number;
  onReady: (cb: DebouncedCallback<[string]>) => void;
}) {
  const debounced = useDebouncedCallback(fn, delay);
  onReady(debounced);
  return null;
}

describe("useDebouncedCallback", () => {
  it("debounces calls and fires once after the delay", () => {
    vi.useFakeTimers();
    const fn = vi.fn();
    let cb: DebouncedCallback<[string]>;
    mount(createElement(Harness, { fn, delay: 300, onReady: (c) => (cb = c) }));

    act(() => {
      cb!("a");
      cb!("b");
      cb!("c");
    });
    expect(fn).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(300);
    });
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn).toHaveBeenLastCalledWith("c");
  });

  it("FLUSHES the pending call on unmount (does not drop trailing edits)", () => {
    vi.useFakeTimers();
    const fn = vi.fn();
    let cb: DebouncedCallback<[string]>;
    mount(createElement(Harness, { fn, delay: 600, onReady: (c) => (cb = c) }));

    act(() => {
      cb!("trailing");
    });
    expect(fn).not.toHaveBeenCalled();

    // Unmount before the timer fires — the pending call must still run.
    unmount();
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn).toHaveBeenLastCalledWith("trailing");
  });

  it("flush() runs the pending call immediately and only once", () => {
    vi.useFakeTimers();
    const fn = vi.fn();
    let cb: DebouncedCallback<[string]>;
    mount(createElement(Harness, { fn, delay: 600, onReady: (c) => (cb = c) }));

    act(() => {
      cb!("x");
      cb!.flush();
    });
    expect(fn).toHaveBeenCalledTimes(1);
    // Advancing time must not double-fire.
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("cancel() drops the pending call", () => {
    vi.useFakeTimers();
    const fn = vi.fn();
    let cb: DebouncedCallback<[string]>;
    mount(createElement(Harness, { fn, delay: 600, onReady: (c) => (cb = c) }));

    act(() => {
      cb!("y");
      cb!.cancel();
      vi.advanceTimersByTime(1000);
    });
    expect(fn).not.toHaveBeenCalled();
  });
});
