import { describe, expect, it } from "vitest";
import { emptyState } from "@/components/findings/finding-form-state";
import {
  hasBlockingError,
  issuesByField,
  validateFindingForm,
} from "./finding-validation";

describe("validateFindingForm", () => {
  it("flags a missing title as a blocking error", () => {
    const issues = validateFindingForm(emptyState());
    const title = issues.find((i) => i.field === "f-title");
    expect(title?.severity).toBe("error");
    expect(hasBlockingError(issues)).toBe(true);
  });

  it("passes with a title and otherwise empty form", () => {
    const issues = validateFindingForm({ ...emptyState(), title: "XSS" });
    expect(hasBlockingError(issues)).toBe(false);
    expect(issues).toHaveLength(0);
  });

  it("warns (non-blocking) on a malformed CWE", () => {
    const issues = validateFindingForm({ ...emptyState(), title: "x", cwe: "89" });
    const cwe = issues.find((i) => i.field === "f-cwe");
    expect(cwe?.severity).toBe("warning");
    expect(hasBlockingError(issues)).toBe(false);
  });

  it("accepts a well-formed CWE (case-insensitive)", () => {
    const issues = validateFindingForm({ ...emptyState(), title: "x", cwe: "cwe-79" });
    expect(issues.find((i) => i.field === "f-cwe")).toBeUndefined();
  });

  it("warns on a malformed CVE and accepts a valid one", () => {
    const bad = validateFindingForm({ ...emptyState(), title: "x", cve: "CVE-99" });
    expect(bad.find((i) => i.field === "f-cve")?.severity).toBe("warning");
    const ok = validateFindingForm({ ...emptyState(), title: "x", cve: "CVE-2024-1234" });
    expect(ok.find((i) => i.field === "f-cve")).toBeUndefined();
  });

  it("warns on non-positive-integer line numbers", () => {
    const issues = validateFindingForm({
      ...emptyState(),
      title: "x",
      ev_start_line: "0",
      ev_end_line: "1.5",
    });
    expect(issues.find((i) => i.field === "f-ev-start")?.severity).toBe("warning");
    expect(issues.find((i) => i.field === "f-ev-end")?.severity).toBe("warning");
  });

  it("warns when start line > end line", () => {
    const issues = validateFindingForm({
      ...emptyState(),
      title: "x",
      ev_start_line: "20",
      ev_end_line: "10",
    });
    const end = issues.find((i) => i.field === "f-ev-end");
    expect(end?.severity).toBe("warning");
    expect(end?.messageKey).toContain("lineRange");
  });

  it("accepts start == end", () => {
    const issues = validateFindingForm({
      ...emptyState(),
      title: "x",
      ev_start_line: "10",
      ev_end_line: "10",
    });
    expect(issues).toHaveLength(0);
  });
});

describe("issuesByField", () => {
  it("keeps the first issue per field (error before warning)", () => {
    const map = issuesByField([
      { field: "f-title", severity: "error", messageKey: "a" },
      { field: "f-title", severity: "warning", messageKey: "b" },
    ]);
    expect(map["f-title"].severity).toBe("error");
  });
});
