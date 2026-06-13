import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the Tauri IPC bridge before importing the wrappers under test. The mock
// records the command name + args each wrapper invokes, so we can assert the
// camelCase arg mapping without a real Tauri runtime.
const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invoke(...args),
}));

import {
  addEvidenceImage,
  aiComplete,
  aiSetConfig,
  asIpcError,
  createReport,
  getReport,
  importFindings,
  listFindings,
  updateReport,
} from "./ipc";
import type { AiConfig, ImportFormat, NewReport, ReportPatch } from "./types";

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue(undefined);
});

describe("ipc wrappers map to the right command + camelCase args", () => {
  it("getReport passes the id under `id`", async () => {
    await getReport("abc");
    expect(invoke).toHaveBeenCalledWith("get_report", { id: "abc" });
  });

  it("listFindings uses the camelCase reportId arg", async () => {
    await listFindings("rep-1");
    expect(invoke).toHaveBeenCalledWith("list_findings", { reportId: "rep-1" });
  });

  it("createReport wraps the payload under `input`", async () => {
    const input = { title: "T" } as unknown as NewReport;
    await createReport(input);
    expect(invoke).toHaveBeenCalledWith("create_report", { input });
  });

  it("updateReport passes id + patch", async () => {
    const patch = { title: "new" } as unknown as ReportPatch;
    await updateReport("rep-9", patch);
    expect(invoke).toHaveBeenCalledWith("update_report", { id: "rep-9", patch });
  });

  it("importFindings forwards format + content positionally into named args", async () => {
    await importFindings("rep-2", "sarif" as ImportFormat, "{}");
    expect(invoke).toHaveBeenCalledWith("import_findings", {
      reportId: "rep-2",
      format: "sarif",
      content: "{}",
    });
  });

  it("addEvidenceImage maps caption/mime/data alongside findingId", async () => {
    await addEvidenceImage("f-1", "cap", "image/png", [1, 2, 3]);
    expect(invoke).toHaveBeenCalledWith("add_evidence_image", {
      findingId: "f-1",
      caption: "cap",
      mime: "image/png",
      data: [1, 2, 3],
    });
  });
});

describe("aiSetConfig key handling", () => {
  const config = { enabled: true, provider: "ollama" } as unknown as AiConfig;

  it("sends apiKey: null when no key is provided (keep existing)", async () => {
    await aiSetConfig(config);
    expect(invoke).toHaveBeenCalledWith("ai_set_config", { config, apiKey: null });
  });

  it("forwards an explicit key", async () => {
    await aiSetConfig(config, "sk-123");
    expect(invoke).toHaveBeenCalledWith("ai_set_config", { config, apiKey: "sk-123" });
  });

  it("forwards an empty string (clear the key) as-is", async () => {
    await aiSetConfig(config, "");
    expect(invoke).toHaveBeenCalledWith("ai_set_config", { config, apiKey: "" });
  });
});

describe("aiComplete optional system arg", () => {
  it("defaults system to null", async () => {
    await aiComplete("hello");
    expect(invoke).toHaveBeenCalledWith("ai_complete", { system: null, prompt: "hello" });
  });

  it("forwards a provided system prompt", async () => {
    await aiComplete("hello", "be terse");
    expect(invoke).toHaveBeenCalledWith("ai_complete", { system: "be terse", prompt: "hello" });
  });
});

describe("a wrapper surfaces rejections to the caller", () => {
  it("propagates the thrown IpcError-shaped value", async () => {
    invoke.mockRejectedValueOnce({ kind: "vault_locked", message: "Vault is locked" });
    await expect(getReport("x")).rejects.toEqual({
      kind: "vault_locked",
      message: "Vault is locked",
    });
  });
});

describe("asIpcError", () => {
  it("passes through a well-formed {kind, message}", () => {
    expect(asIpcError({ kind: "io", message: "disk full" })).toEqual({
      kind: "io",
      message: "disk full",
    });
  });

  it("defaults kind to 'error' when only a message is present", () => {
    expect(asIpcError({ message: "boom" })).toEqual({ kind: "error", message: "boom" });
  });

  it("wraps a raw string", () => {
    expect(asIpcError("plain failure")).toEqual({ kind: "error", message: "plain failure" });
  });

  it("falls back to an Unknown error for unrecognized values", () => {
    expect(asIpcError(null)).toEqual({ kind: "error", message: "Unknown error" });
    expect(asIpcError(42)).toEqual({ kind: "error", message: "Unknown error" });
    expect(asIpcError({ kind: 7, message: 9 })).toEqual({
      kind: "error",
      message: "Unknown error",
    });
  });
});
