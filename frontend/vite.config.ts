import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ['**/src-tauri/**', '**/crates/**'],
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    assetsInlineLimit: 4096,
    rollupOptions: {
      output: {
        // 按依赖目录稳定分包，避免 React 19 子入口（react-dom/client、scheduler）落入主业务包
        manualChunks(id) {
          if (
            id.includes('/node_modules/react/') ||
            id.includes('/node_modules/react-dom/') ||
            id.includes('/node_modules/scheduler/') ||
            id.includes('\\node_modules\\react\\') ||
            id.includes('\\node_modules\\react-dom\\') ||
            id.includes('\\node_modules\\scheduler\\')
          ) {
            return 'react';
          }
          if (id.includes('/node_modules/@tauri-apps/') || id.includes('\\node_modules\\@tauri-apps\\')) {
            return 'tauri';
          }
          return undefined;
        },
      },
    },
  },
});
