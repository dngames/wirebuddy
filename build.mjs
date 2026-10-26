import { build } from "esbuild";
import { cpSync, mkdirSync } from "node:fs";

await build({
  entryPoints: ["src/server/main.ts"],
  outfile: "dist/server/main.js",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  packages: "external",
  sourcemap: true,
  banner: { js: "#!/usr/bin/env node" },
  logLevel: "info",
});

await build({
  entryPoints: ["src/web/main.ts"],
  outfile: "dist/web/app.js",
  bundle: true,
  platform: "browser",
  format: "esm",
  target: "es2022",
  sourcemap: true,
  logLevel: "info",
});

mkdirSync("dist/web", { recursive: true });
cpSync("src/web/index.html", "dist/web/index.html");
cpSync("src/web/styles.css", "dist/web/styles.css");

