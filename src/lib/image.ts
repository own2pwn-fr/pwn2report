// Helpers for evidence-image byte handling and MIME inference.

import i18n from "@/i18n";

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
        reject(new Error(i18n.t("image.canvasExportFailed")));
        return;
      }
      blob
        .arrayBuffer()
        .then((buf) => resolve(Array.from(new Uint8Array(buf))))
        .catch(reject);
    }, "image/png");
  });
}

/**
 * Formats that can be re-encoded losslessly/safely through a <canvas> to strip
 * any embedded metadata (EXIF/GPS/device/profile chunks). Other formats (SVG,
 * animated GIF) are passed through unchanged because canvas re-encoding would
 * either be unsafe (SVG can carry script) or lossy (drops animation).
 */
const STRIPPABLE_MIMES = new Set(["image/png", "image/jpeg", "image/webp", "image/bmp", "image/avif"]);

/**
 * Re-encode raw image bytes through a <canvas>, dropping ALL embedded metadata
 * (EXIF, GPS coordinates, device info, color profiles, comments). The decoded
 * pixels are redrawn onto a bare canvas and exported fresh, so nothing but the
 * visible image survives.
 *
 * PNG/BMP/AVIF inputs are re-encoded to lossless PNG; JPEG/WebP keep their
 * format at high quality to avoid bloating photos. Formats that cannot be
 * safely/faithfully rasterized (SVG, GIF) are returned untouched.
 *
 * Falls back to the original bytes if decoding fails (e.g. an exotic codec the
 * browser cannot paint) so an import never silently loses the image.
 */
export function stripImageMetadata(
  bytes: number[] | Uint8Array,
  mime: string,
): Promise<{ bytes: number[]; mime: string }> {
  const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const passthrough = { bytes: Array.from(input), mime };

  if (!STRIPPABLE_MIMES.has(mime)) {
    return Promise.resolve(passthrough);
  }

  // JPEG/WebP stay in their (lossy) format at high quality; everything else
  // becomes lossless PNG.
  const outMime = mime === "image/jpeg" || mime === "image/webp" ? mime : "image/png";
  const quality = 0.92;

  return new Promise((resolve) => {
    const url = objectUrlFromBytes(input, mime);
    const img = new Image();
    img.onload = () => {
      try {
        const canvas = document.createElement("canvas");
        canvas.width = img.naturalWidth || img.width;
        canvas.height = img.naturalHeight || img.height;
        const ctx = canvas.getContext("2d");
        if (!canvas.width || !canvas.height || !ctx) {
          URL.revokeObjectURL(url);
          resolve(passthrough);
          return;
        }
        ctx.drawImage(img, 0, 0);
        canvas.toBlob(
          (blob) => {
            URL.revokeObjectURL(url);
            if (!blob) {
              resolve(passthrough);
              return;
            }
            blob
              .arrayBuffer()
              .then((buf) => resolve({ bytes: Array.from(new Uint8Array(buf)), mime: outMime }))
              .catch(() => resolve(passthrough));
          },
          outMime,
          quality,
        );
      } catch {
        URL.revokeObjectURL(url);
        resolve(passthrough);
      }
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      resolve(passthrough);
    };
    img.src = url;
  });
}
