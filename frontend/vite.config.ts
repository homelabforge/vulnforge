import path from "path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  cacheDir: path.resolve(__dirname, "node_modules/.vite-cache"),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    // Reduce memory usage in CI environments
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        // Vite 8 (rolldown) requires manualChunks as a function, not an object
        manualChunks(id) {
          if (['react', 'react-dom', 'react-router-dom'].some((m) => id.includes(`/${m}/`))) {
            return 'react-vendor';
          }
          if (id.includes('/@tanstack/react-query/')) return 'query-vendor';
          if (id.includes('/recharts/')) return 'charts-vendor';
          if (['lucide-react', 'sonner', 'clsx', 'tailwind-merge'].some((m) => id.includes(`/${m}/`))) {
            return 'ui-vendor';
          }
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": {
        target: process.env.VITE_API_URL || "http://localhost:8787",
        changeOrigin: true,
      },
    },
  },
});
