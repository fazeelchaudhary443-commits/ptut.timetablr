import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { cpSync, existsSync, mkdirSync } from "fs";

export default defineConfig({
  plugins: [
    react(),
    {
      name: "copy-standalone",
      closeBundle() {
        if (existsSync("standalone/ptut-hub.html")) {
          mkdirSync("dist/standalone", { recursive: true });
          cpSync(
            "standalone/ptut-hub.html",
            "dist/standalone/ptut-hub.html"
          );
        }
      }
    }
  ]
});
