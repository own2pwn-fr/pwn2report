import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_IDLE_LOCK_MINUTES,
  getIdleLockMinutes,
  setIdleLockMinutes,
} from "./use-idle-lock";

afterEach(() => {
  localStorage.clear();
});

describe("idle-lock setting persistence", () => {
  it("defaults to DEFAULT_IDLE_LOCK_MINUTES when unset", () => {
    expect(getIdleLockMinutes()).toBe(DEFAULT_IDLE_LOCK_MINUTES);
  });

  it("round-trips a stored value", () => {
    setIdleLockMinutes(30);
    expect(getIdleLockMinutes()).toBe(30);
  });

  it("treats 0 as a valid 'off' value (not the default)", () => {
    setIdleLockMinutes(0);
    expect(getIdleLockMinutes()).toBe(0);
  });

  it("clamps negatives to 0 and rounds fractional minutes", () => {
    setIdleLockMinutes(-5);
    expect(getIdleLockMinutes()).toBe(0);
    setIdleLockMinutes(12.6);
    expect(getIdleLockMinutes()).toBe(13);
  });

  it("falls back to the default when the stored value is garbage", () => {
    localStorage.setItem("pwn2report.idleLockMinutes", "not-a-number");
    expect(getIdleLockMinutes()).toBe(DEFAULT_IDLE_LOCK_MINUTES);
  });
});
