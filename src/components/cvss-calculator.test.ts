import { describe, expect, it } from "vitest";
import {
  buildVector,
  compute,
  defaultSelections,
  selectionsFromVector,
  versionOf,
} from "./cvss-calculator";

describe("versionOf", () => {
  it("detects the version from the vector prefix", () => {
    expect(versionOf("CVSS:3.1/AV:N/AC:L")).toBe("3.1");
    expect(versionOf("CVSS:4.0/AV:N/AC:L")).toBe("4.0");
  });

  it("returns null for unknown / unsupported prefixes", () => {
    expect(versionOf("CVSS:2.0/AV:N")).toBeNull();
    expect(versionOf("CVSS:3.0/AV:N")).toBeNull();
    expect(versionOf("garbage")).toBeNull();
  });
});

describe("buildVector / selectionsFromVector round-trip", () => {
  it("rebuilds the canonical 3.1 default vector from default selections", () => {
    expect(buildVector("3.1", defaultSelections("3.1"))).toBe(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    );
  });

  it("parses a vector and rebuilds it identically (3.1)", () => {
    const v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    expect(buildVector("3.1", selectionsFromVector("3.1", v))).toBe(v);
  });

  it("ignores unknown/invalid segments and falls back to defaults", () => {
    // ZZ:X is not a metric; AV gets a bogus value and must fall back to default N.
    const sel = selectionsFromVector("3.1", "CVSS:3.1/ZZ:X/AV:Q/C:H");
    expect(sel.AV).toBe("N");
    expect(sel.C).toBe("H");
  });
});

describe("compute (CVSS 3.1)", () => {
  it("scores the canonical worst-case vector as 9.8 / Critical", () => {
    const { score, severity } = compute(
      "3.1",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    );
    expect(score).toBe(9.8);
    expect(severity).toBe("CRITICAL");
  });

  it("scores a low-impact vector in the Medium band", () => {
    const { score, severity } = compute(
      "3.1",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    );
    expect(score).toBe(4.3);
    expect(severity).toBe("MEDIUM");
  });

  it("scores an all-None vector as 0 / None", () => {
    const { score, severity } = compute(
      "3.1",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    );
    expect(score).toBe(0);
    expect(severity).toBe("NONE");
  });
});

describe("compute (CVSS 4.0)", () => {
  it("scores the canonical worst-case vector as 10.0 / Critical", () => {
    const { score, severity } = compute(
      "4.0",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    );
    expect(score).toBe(10);
    expect(severity).toBe("CRITICAL");
  });

  it("scores an all-None impact vector as 0 / None", () => {
    const { score, severity } = compute(
      "4.0",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    );
    expect(score).toBe(0);
    expect(severity).toBe("NONE");
  });
});
