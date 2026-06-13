import { describe, expect, it } from "vitest";
import { sniffImportFormat } from "./import-sniff";

describe("sniffImportFormat", () => {
  it("detects SARIF from a $schema reference", () => {
    const sarif = JSON.stringify({
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [],
    });
    expect(sniffImportFormat(sarif)).toBe("sarif");
  });

  it("detects SARIF from version + runs without a schema", () => {
    expect(sniffImportFormat('{ "version": "2.1.0", "runs": [] }')).toBe("sarif");
  });

  it("detects SARIF from a bare runs array", () => {
    expect(sniffImportFormat('{ "runs": [ { "tool": {} } ] }')).toBe("sarif");
  });

  it("detects Nessus from its XML root element", () => {
    expect(sniffImportFormat('<?xml version="1.0"?>\n<NessusClientData_v2>')).toBe("nessus");
  });

  it("detects Burp from its issues XML root", () => {
    expect(sniffImportFormat('<?xml version="1.0"?>\n<issues burpVersion="2023.1">')).toBe("burp");
  });

  it("detects Nuclei JSONL from template-id + info", () => {
    const line = '{"template-id":"CVE-2021-1234","info":{"name":"x","severity":"high"}}';
    expect(sniffImportFormat(line)).toBe("nuclei");
  });

  it("detects CSV from the file extension", () => {
    expect(sniffImportFormat("anything at all", "results.csv")).toBe("csv");
  });

  it("detects CSV from a comma-delimited header line", () => {
    expect(sniffImportFormat("title,severity,cwe\nXSS,high,CWE-79")).toBe("csv");
  });

  it("returns null when nothing matches (caller falls back to manual)", () => {
    expect(sniffImportFormat("just some prose with no structure")).toBeNull();
    expect(sniffImportFormat("<unknownRoot>")).toBeNull();
    expect(sniffImportFormat('{ "foo": "bar" }')).toBeNull();
  });
});
