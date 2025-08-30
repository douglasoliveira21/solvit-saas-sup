import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      'solvitsoft.com.br',
      'www.solvitsoft.com.br',
      '82.112.244.92'
    ]
  }
})
