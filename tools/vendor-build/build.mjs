import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const shim = path.join(__dirname, "crypto-shim.js");
const common = {
  bundle: true, format: "esm", platform: "neutral", minify: true,
  legalComments: "inline", mainFields: ["module", "main"], target: "es2020",
  alias: { crypto: shim },
};
await build({ ...common, entryPoints: ["forge-entry.js"], outfile: "../../static/vendor/forge.mjs" });
await build({ ...common, entryPoints: ["chacha-entry.js"], outfile: "../../static/vendor/noble-ciphers.mjs" });
await build({ ...common, entryPoints: ["curves-entry.js"], outfile: "../../static/vendor/noble-curves.mjs" });
console.log("vendor OK");
