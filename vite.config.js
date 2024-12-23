import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/plugin-vulnerability-scanner/',  // Match GitHub Pages repository name
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      external: ['/plugin-vulnerability-scanner/src/main.jsx'],
      output: {
        manualChunks: undefined,
      }
    }
  }
});