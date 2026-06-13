import { describe, expect, it } from "vitest";
import {
  confidenceKey,
  formatDate,
  formatDateTime,
  reportTypeKey,
  severityKey,
  SEVERITY_ORDER,
  severityRank,
  triageKey,
} from "./format";

describe("formatDate", () => {
  it("formats a valid ISO timestamp into a localized date string", () => {
    const out = formatDate("2026-01-15T10:30:00.000Z");
    // We don't assert the exact locale rendering (CI-dependent), only that the
    // year and a non-empty result come through and it isn't the raw ISO input.
    expect(out).toContain("2026");
    expect(out).not.toBe("2026-01-15T10:30:00.000Z");
  });

  it("returns the original string for an unparseable value", () => {
    expect(formatDate("not-a-date")).toBe("not-a-date");
    expect(formatDate("")).toBe("");
  });
});

describe("formatDateTime", () => {
  it("includes the year for a valid timestamp", () => {
    expect(formatDateTime("2026-01-15T10:30:00.000Z")).toContain("2026");
  });

  it("returns the original string for an unparseable value", () => {
    expect(formatDateTime("garbage")).toBe("garbage");
  });
});

describe("severityRank / SEVERITY_ORDER", () => {
  it("ranks critical above high above the rest, info last", () => {
    expect(severityRank("critical")).toBe(0);
    expect(severityRank("critical")).toBeLessThan(severityRank("high"));
    expect(severityRank("high")).toBeLessThan(severityRank("medium"));
    expect(severityRank("medium")).toBeLessThan(severityRank("low"));
    expect(severityRank("low")).toBeLessThan(severityRank("info"));
  });

  it("produces a stable critical-first sort order", () => {
    const shuffled = ["low", "critical", "info", "high", "medium"] as const;
    const sorted = [...shuffled].sort((a, b) => severityRank(a) - severityRank(b));
    expect(sorted).toEqual(["critical", "high", "medium", "low", "info"]);
  });

  it("covers every value in SEVERITY_ORDER", () => {
    expect(SEVERITY_ORDER).toEqual(["critical", "high", "medium", "low", "info"]);
  });
});

describe("i18n key builders", () => {
  it("namespace their values", () => {
    expect(severityKey("high")).toBe("severity.high");
    expect(confidenceKey("high")).toBe("confidence.high");
    expect(triageKey("false_positive")).toBe("triage.false_positive");
    expect(reportTypeKey("web_pentest")).toBe("reportType.web_pentest");
  });
});
