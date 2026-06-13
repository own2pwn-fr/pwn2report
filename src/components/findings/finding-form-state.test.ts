import { describe, expect, it } from "vitest";
import {
  emptyState,
  stateFromFinding,
  toNewFinding,
  toPatch,
  type FindingFormState,
} from "./finding-form-state";
import type { Finding } from "@/lib/types";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    report_id: "r1",
    sort_order: 0,
    title: "Test",
    severity: "medium",
    confidence: "medium",
    kind: "manual",
    cwe: null,
    cve: null,
    cvss_vector: null,
    cvss_score: null,
    triage_status: "open",
    triage_note: null,
    description: {
      summary: "",
      root_cause: "",
      attack_vector: "",
      business_impact: "",
      technical_details: "",
    },
    remediation: { fix: "", code_patch: null, references: [] },
    evidence: null,
    poc: null,
    refs: [],
    tags: [],
    custom_fields: {},
    mappings: [],
    created_at: "2026-01-01",
    updated_at: "2026-01-01",
    ...overrides,
  };
}

describe("finding-form-state retest/mappings/custom_fields", () => {
  it("defaults to no retest and empty mappings/custom fields", () => {
    const s = emptyState();
    expect(s.retest_status).toBe("not_retested");
    expect(s.retest_date).toBe("");
    expect(s.mappings).toEqual([]);
    expect(s.custom_fields).toEqual({});
  });

  it("drops the retest date when status is not_retested", () => {
    const s: FindingFormState = {
      ...emptyState(),
      title: "X",
      retest_status: "not_retested",
      retest_date: "2026-06-01",
    };
    expect(toNewFinding(s).retest_date).toBeNull();
  });

  it("keeps the retest date when an outcome is recorded", () => {
    const s: FindingFormState = {
      ...emptyState(),
      title: "X",
      retest_status: "fixed",
      retest_date: " 2026-06-01 ",
    };
    expect(toPatch(s).retest_date).toBe("2026-06-01");
    expect(toPatch(s).retest_status).toBe("fixed");
  });

  it("drops incomplete mappings and trims complete ones", () => {
    const s: FindingFormState = {
      ...emptyState(),
      title: "X",
      mappings: [
        { framework: "owasp_top10", id: " A03:2021 ", name: " Injection " },
        { framework: "cwe", id: "", name: null },
        { framework: "", id: "X", name: null },
      ],
    };
    expect(toNewFinding(s).mappings).toEqual([
      { framework: "owasp_top10", id: "A03:2021", name: "Injection" },
    ]);
  });

  it("drops custom fields with an empty key and trims keys", () => {
    const s: FindingFormState = {
      ...emptyState(),
      title: "X",
      custom_fields: { " env ": "prod", "": "ignored", ticket: "ABC-1" },
    };
    expect(toPatch(s).custom_fields).toEqual({ env: "prod", ticket: "ABC-1" });
  });

  it("round-trips a finding's retest/mappings/custom fields into form state", () => {
    const f = baseFinding({
      retest_status: "partially_fixed",
      retest_date: "2026-05-05",
      mappings: [{ framework: "nist", id: "AC-2", name: null }],
      custom_fields: { ticket: "ABC-1" },
    });
    const s = stateFromFinding(f);
    expect(s.retest_status).toBe("partially_fixed");
    expect(s.retest_date).toBe("2026-05-05");
    expect(s.mappings).toEqual([{ framework: "nist", id: "AC-2", name: null }]);
    expect(s.custom_fields).toEqual({ ticket: "ABC-1" });
  });
});
