import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Set VITE_API_BASE to point at the FastAPI server (default http://localhost:8000).
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
});
