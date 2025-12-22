import path from "path";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
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
        manualChunks: {
          // Split React and React-related libraries into separate chunk
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          // React Query in its own chunk for better caching
          'query-vendor': ['@tanstack/react-query'],
          // Charts library is large - separate chunk
          'charts-vendor': ['recharts'],
          // UI utilities
          'ui-vendor': ['lucide-react', 'sonner', 'clsx', 'tailwind-merge'],
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
