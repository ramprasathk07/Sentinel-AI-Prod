import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // Proxy API + webhook calls to local FastAPI (port 8005) in dev.
    // Keeps VITE_API_URL empty so all fetch URLs are relative paths.
    proxy: {
      '/api': { target: 'http://localhost:8005', changeOrigin: true },
      '/webhook': { target: 'http://localhost:8005', changeOrigin: true },
    },
  },
})
