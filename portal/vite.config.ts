// Production build of the portal (ADR-0020, § 1): no source map, hashed
// file names, no inline asset (the CSP refuses data: URLs), a Vite manifest
// for the budget of the login page (removed by scripts/pack.mjs).
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [svelte()],
  base: "/",
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    manifest: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    reportCompressedSize: false,
  },
});
