// Build script for the Kernel front‑end using esbuild
// Run with: node scripts/build-frontend.js

import { build } from "esbuild";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

await build({
  entryPoints: [resolve(__dirname, "../static/js/main.js")],
  bundle: true,
  minify: true,
  sourcemap: true,
  target: ["chrome120", "firefox120", "safari15"],
  outfile: resolve(__dirname, "../static/js/build/bundle.js"),
  define: {
    // Ensure Node‑specific globals are not inlined unintentionally
    "process.env.NODE_ENV": "\"production\"",
  },
  loader: {
    ".js": "js",
    ".mjs": "js",
  },
});

console.log("✅ Front‑end bundled to static/js/build/bundle.js");

