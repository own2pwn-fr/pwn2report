import { describe, expect, it } from "vitest";
import { isTypingTarget } from "./use-hotkeys";

describe("isTypingTarget", () => {
  it("is true for input, textarea and select elements", () => {
    expect(isTypingTarget(document.createElement("input"))).toBe(true);
    expect(isTypingTarget(document.createElement("textarea"))).toBe(true);
    expect(isTypingTarget(document.createElement("select"))).toBe(true);
  });

  it("is true for contentEditable elements", () => {
    const div = document.createElement("div");
    div.contentEditable = "true";
    // happy-dom reflects isContentEditable from the attribute.
    Object.defineProperty(div, "isContentEditable", { value: true });
    expect(isTypingTarget(div)).toBe(true);
  });

  it("is false for buttons, plain divs and null", () => {
    expect(isTypingTarget(document.createElement("button"))).toBe(false);
    expect(isTypingTarget(document.createElement("div"))).toBe(false);
    expect(isTypingTarget(null)).toBe(false);
  });
});
