import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/wasm-guardian/', 
  esbuild: {
    loader: 'jsx',
    include: /src\/.*\.[jt]sx?$/,
  }
})
