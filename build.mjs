import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync } from "node:fs";

const { version } = JSON.parse(readFileSync("package.json", "utf8"));
const define = { __VERSION__: JSON.stringify(version) };

await build({
  entryPoints: ["src/server/main.ts"],
  outfile: "dist/server/main.js",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  define,
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
  define,
  sourcemap: true,
  logLevel: "info",
});

mkdirSync("dist/web", { recursive: true });
cpSync("src/web/index.html", "dist/web/index.html");
cpSync("src/web/styles.css", "dist/web/styles.css");

