import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

const isTest = process.env.VITEST === "true";

export default defineConfig({
  plugins: [react()],
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
