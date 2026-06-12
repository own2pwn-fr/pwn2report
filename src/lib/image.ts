// Helpers for evidence-image byte handling and MIME inference.

const EXT_TO_MIME: Record<string, string> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  bmp: "image/bmp",
  svg: "image/svg+xml",
  avif: "image/avif",
};

/** Image file extensions accepted by the gallery's file picker. */
export const IMAGE_EXTENSIONS = Object.keys(EXT_TO_MIME);

/** Infer a MIME type from a file path/extension, defaulting to PNG. */
export function mimeFromPath(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  return EXT_TO_MIME[ext] ?? "image/png";
}

/** Build an object URL from raw image bytes. Caller must revoke it. */
export function objectUrlFromBytes(bytes: number[] | Uint8Array, mime: string): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  // Copy into a fresh ArrayBuffer-backed view so the Blob owns standalone bytes.
  const blob = new Blob([arr.slice()], { type: mime });
  return URL.createObjectURL(blob);
}

/** Convert a canvas to PNG bytes via toBlob (lossless, baked pixels). */
export function canvasToPngBytes(canvas: HTMLCanvasElement): Promise<number[]> {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) {
        reject(new Error("Canvas export failed"));
        return;
      }
      blob
        .arrayBuffer()
        .then((buf) => resolve(Array.from(new Uint8Array(buf))))
        .catch(reject);
    }, "image/png");
  });
}
