import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/check-flow': { target: 'http://localhost:8000', changeOrigin: true },
      '/health': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/cloud': { target: 'https://localhost:8001', changeOrigin: true, secure: false },
      '/api/v1': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
  preview: {
    port: 5173,
    proxy: {
      '/check-flow': { target: 'http://localhost:8000', changeOrigin: true },
      '/health': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/cloud': { target: 'https://localhost:8001', changeOrigin: true, secure: false },
      '/api/v1': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
})
