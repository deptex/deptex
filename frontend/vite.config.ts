import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { sentryVitePlugin } from "@sentry/vite-plugin";
import path from "path";

const isTest = process.env.VITEST === "true";

// Source-map upload only runs when a build-time auth token is present (CI/prod
// build) — local `npm run build` just emits hidden maps with no upload. The
// plugin must be LAST in the plugins array so maps are generated before upload.
const sentryPlugins =
  process.env.SENTRY_AUTH_TOKEN && !isTest
    ? [
        sentryVitePlugin({
          org: process.env.SENTRY_ORG,
          project: process.env.SENTRY_PROJECT,
          authToken: process.env.SENTRY_AUTH_TOKEN,
          sourcemaps: { filesToDeleteAfterUpload: ["./dist/**/*.map"] },
        }),
      ]
    : [];

export default defineConfig({
  build: { sourcemap: "hidden" },
  plugins: [react(), ...sentryPlugins],
  // Supply dummy Supabase env vars in tests so components importing supabase don't throw
  define: isTest
    ? {
        "import.meta.env.VITE_SUPABASE_URL": JSON.stringify("https://test.supabase.co"),
        "import.meta.env.VITE_SUPABASE_ANON_KEY": JSON.stringify("test-anon-key"),
      }
    : undefined,
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    open: true,
    port: 3000,
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
  },
});
