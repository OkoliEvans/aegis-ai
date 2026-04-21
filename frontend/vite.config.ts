import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

export default defineConfig({
  envDir: "..",
  plugins: [
    react(),
    nodePolyfills({
      globals: {
        Buffer: true,
        process: true
      }
    })
  ],
  resolve: {
    dedupe: ["react", "react-dom", "wagmi", "@tanstack/react-query", "viem"]
  }
});
