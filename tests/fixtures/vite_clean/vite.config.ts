import { defineConfig } from "vite";

export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify("1.0.0") },
  server: { proxy: { "/api": "http://localhost:3001" } },
  build: { sourcemap: false },
});
