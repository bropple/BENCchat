import { defineConfig } from "vite";

// Wails serves the built frontend from frontend/dist and injects its runtime
// bindings at load time. No framework — vanilla TS keeps the protocol-first
// project lean, matching the "less tooling to lean on" spirit of CLAUDE.md.
export default defineConfig({
  build: {
    // Emit predictable asset names; the app is loaded from an embedded FS.
    assetsDir: "assets",
    emptyOutDir: true,
  },
});
