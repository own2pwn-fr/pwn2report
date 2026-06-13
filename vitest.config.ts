import { defineConfig } from "vitest/config";
import { fileURLToPath, URL } from "node:url";

// Standalone Vitest config: kept separate from vite.config.ts so the Tauri
// dev-server options (fixed port, src-tauri ignores) don't bleed into tests.
// Tests are CI-friendly — no real Tauri runtime or network is touched; the
// `@tauri-apps/api/core` invoke bridge is mocked per-suite via vi.mock.
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "happy-dom",
    globals: false,
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
