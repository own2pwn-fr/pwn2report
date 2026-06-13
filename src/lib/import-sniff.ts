import type { ImportFormat } from "./types";

/**
 * Best-effort detection of a scanner export format from the raw file content
 * (and optionally its filename). Returns `null` when nothing matches with
 * enough confidence — callers should then fall back to asking the user.
 *
 * Heuristics (cheap, content-based; mirrors the backend parser expectations):
 *  - JSON whose top level has a `runs` array or a SARIF `version` → SARIF
 *  - XML with a `<NessusClientData` root → Nessus
 *  - XML with `<issues` / Burp markers → Burp Suite
 *  - JSONL where the first object has `template-id`/`info` → Nuclei
 *  - `.csv` filename or comma-delimited header-looking first line → CSV
 */
export function sniffImportFormat(content: string, fileName?: string | null): ImportFormat | null {
  const trimmed = content.trimStart();
  const lower = trimmed.toLowerCase();
  const ext = fileName?.toLowerCase().split(".").pop() ?? null;

  // XML-based scanners are easy to disambiguate by their root element.
  if (trimmed.startsWith("<")) {
    if (lower.includes("<nessusclientdata")) return "nessus";
    if (lower.includes("<issues") || lower.includes("burpversion")) return "burp";
    return null;
  }

  // SARIF / secai are JSON objects starting with `{`.
  if (trimmed.startsWith("{")) {
    // A SARIF log always carries a top-level `runs` array; many also pin
    // `"version": "2.1.0"` and a `$schema` mentioning sarif.
    if (/"\$schema"\s*:\s*"[^"]*sarif/i.test(trimmed)) return "sarif";
    if (/"version"\s*:/.test(trimmed) && /"runs"\s*:\s*\[/.test(trimmed)) return "sarif";
    if (/"runs"\s*:\s*\[/.test(trimmed)) return "sarif";

    // Nuclei JSONL: each line is a finding object with `template-id` + `info`.
    // A single-object file (not strictly JSONL) can still be a Nuclei result.
    if (/"template-id"\s*:/.test(trimmed) && /"info"\s*:/.test(trimmed)) return "nuclei";
    return null;
  }

  // CSV: either the filename says so, or the first non-empty line looks like a
  // comma-separated header (multiple comma-delimited tokens, no leading brace).
  if (ext === "csv") return "csv";
  const firstLine = trimmed.split(/\r?\n/, 1)[0] ?? "";
  if (firstLine.includes(",") && firstLine.split(",").length >= 2 && !firstLine.includes("{")) {
    return "csv";
  }

  return null;
}
