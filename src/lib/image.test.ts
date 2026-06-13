import { describe, expect, it } from "vitest";
import { IMAGE_EXTENSIONS, mimeFromPath, objectUrlFromBytes } from "./image";

describe("mimeFromPath", () => {
  it("maps known extensions to their MIME type", () => {
    expect(mimeFromPath("shot.png")).toBe("image/png");
    expect(mimeFromPath("shot.jpg")).toBe("image/jpeg");
    expect(mimeFromPath("shot.jpeg")).toBe("image/jpeg");
    expect(mimeFromPath("anim.gif")).toBe("image/gif");
    expect(mimeFromPath("pic.webp")).toBe("image/webp");
    expect(mimeFromPath("logo.svg")).toBe("image/svg+xml");
    expect(mimeFromPath("photo.avif")).toBe("image/avif");
    expect(mimeFromPath("bitmap.bmp")).toBe("image/bmp");
  });

  it("is case-insensitive on the extension", () => {
    expect(mimeFromPath("SHOT.PNG")).toBe("image/png");
    expect(mimeFromPath("Photo.JpEg")).toBe("image/jpeg");
  });

  it("uses the last extension for multi-dotted names", () => {
    expect(mimeFromPath("archive.tar.png")).toBe("image/png");
    expect(mimeFromPath("my.report.final.jpg")).toBe("image/jpeg");
  });

  it("handles full paths, not just filenames", () => {
    expect(mimeFromPath("/home/user/evidence/poc.webp")).toBe("image/webp");
    expect(mimeFromPath("C:\\Users\\me\\shot.gif")).toBe("image/gif");
  });

  it("defaults to PNG for unknown or missing extensions", () => {
    expect(mimeFromPath("notes.txt")).toBe("image/png");
    expect(mimeFromPath("README")).toBe("image/png");
    expect(mimeFromPath("")).toBe("image/png");
    expect(mimeFromPath("trailing.")).toBe("image/png");
  });
});

describe("IMAGE_EXTENSIONS", () => {
  it("exposes the accepted picker extensions without leading dots", () => {
    expect(IMAGE_EXTENSIONS).toContain("png");
    expect(IMAGE_EXTENSIONS).toContain("jpeg");
    // Every advertised extension must resolve to a real MIME type.
    for (const ext of IMAGE_EXTENSIONS) {
      expect(mimeFromPath(`file.${ext}`)).not.toBe("");
      expect(mimeFromPath(`file.${ext}`)).toMatch(/^image\//);
    }
  });
});

describe("objectUrlFromBytes", () => {
  it("accepts both number[] and Uint8Array and returns a blob URL", () => {
    const fromArray = objectUrlFromBytes([1, 2, 3], "image/png");
    const fromTyped = objectUrlFromBytes(new Uint8Array([1, 2, 3]), "image/png");
    expect(fromArray).toMatch(/^blob:/);
    expect(fromTyped).toMatch(/^blob:/);
    URL.revokeObjectURL(fromArray);
    URL.revokeObjectURL(fromTyped);
  });
});
