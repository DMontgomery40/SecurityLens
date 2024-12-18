import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig(({ command, mode }) => {
  // Load env vars for all modes
  const env = loadEnv(mode, process.cwd(), '');
  
  return {
    plugins: [react()],
    
    // Base URL for GitHub Pages
    base: mode === 'production' ? '/plugin-vulnerability-scanner/' : '/',
    
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src')
      }
    },

    // Development server configuration
    server: {
      // Proxy API requests during development
      proxy: {
        '/.netlify/functions/': {
          target: 'http://localhost:9999',
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path.replace(/^\/.netlify\/functions/, '')
        }
      },
      
      // Security headers
      headers: {
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': [
          "default-src 'self'",
          "connect-src 'self' http://localhost:9999 https://api.github.com",
          "script-src 'self' 'unsafe-inline'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: https:",
          "font-src 'self' data:",
        ].join('; ')
      }
    },

    // Build configuration
    build: {
      // Output directory for production build
      outDir: 'dist',
      
      // Generate sourcemaps for production
      sourcemap: true,
      
      // Minification options
      minify: 'terser',
      terserOptions: {
        compress: {
          drop_console: true,  // Remove console.log in production
          drop_debugger: true
        }
      },
      
      // Configure rollup
      rollupOptions: {
        output: {
          manualChunks: {
            // Split vendor code
            vendor: ['react', 'react-dom', 'lodash'],
            // Split UI components
            ui: ['@/components/ui']
          }
        }
      }
    },

    // Preview configuration (for testing production builds locally)
    preview: {
      headers: {
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': [
          "default-src 'self'",
          "connect-src 'self' https://api.github.com",
          "script-src 'self' 'unsafe-inline'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: https:",
          "font-src 'self' data:",
        ].join('; ')
      }
    },

    // Environment variables to expose to the client
    define: {
      __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
      __DEV__: mode === 'development'
    }
  };
});