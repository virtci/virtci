import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const backendPort = process.env.VIRTCI_BACKEND_PORT || '8080'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: `http://localhost:${backendPort}`, // forward to the rust server
        changeOrigin: true,
      },
    },
  },
})
