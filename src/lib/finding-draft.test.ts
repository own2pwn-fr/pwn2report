import { beforeEach, describe, expect, it } from "vitest";
import { emptyState } from "@/components/findings/finding-form-state";
import { clearDraft, draftKey, loadDraft, saveDraft } from "./finding-draft";

describe("draftKey", () => {
  it("uses the finding id when editing", () => {
    expect(draftKey("finding-1", "report-1")).toContain("finding-1");
  });

  it("namespaces new drafts by report id", () => {
    expect(draftKey(undefined, "report-1")).toContain("new:report-1");
    expect(draftKey(undefined, "report-1")).not.toBe(draftKey(undefined, "report-2"));
  });
});

describe("draft persistence round-trip", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("saves and restores a draft", () => {
    const key = draftKey(undefined, "r");
    const state = { ...emptyState(), title: "WIP", tags: ["a", "b"] };
    saveDraft(key, state);
    const loaded = loadDraft(key);
    expect(loaded?.title).toBe("WIP");
    expect(loaded?.tags).toEqual(["a", "b"]);
  });

  it("returns null for a missing draft", () => {
    expect(loadDraft(draftKey("nope", "r"))).toBeNull();
  });

  it("clears a draft", () => {
    const key = draftKey("f", "r");
    saveDraft(key, emptyState());
    clearDraft(key);
    expect(loadDraft(key)).toBeNull();
  });

  it("ignores corrupt JSON", () => {
    const key = draftKey("f", "r");
    window.localStorage.setItem(key, "{not json");
    expect(loadDraft(key)).toBeNull();
  });
});
