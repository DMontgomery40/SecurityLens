import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/',
  define: {
    global: 'globalThis',
    'process.env': {},
    'process.platform': JSON.stringify('browser'),
    'process.version': JSON.stringify('v16.0.0'),
    'process.browser': true,
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        manualChunks: undefined,
      },
    },
    commonjsOptions: {
      esmExternals: true,
    }
  },
  resolve: {
    alias: {
      stream: 'stream-browserify',
      buffer: 'buffer',
      util: 'util',
      process: 'process/browser',
      path: 'path-browserify',
      url: 'url',
      http: 'http-browserify',
      https: 'https-browserify',
      crypto: 'crypto-browserify',
      os: 'os-browserify/browser',
      assert: 'assert',
      constants: 'constants-browserify',
      fs: false,
      net: false,
      tls: false,
      child_process: false,
    }
  },
  optimizeDeps: {
    esbuildOptions: {
      define: {
        global: 'globalThis'
      }
    }
  }
});
