// The npm package as users get it: packed, installed globally into a folder of its own, then run
// over MCP the way `claude mcp add wirebuddy -- npx -y wirebuddy --mcp` does. Needs the npm registry
// for the dependencies.
// Usage: node test/package.mjs   (after npm run build)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = mkdtempSync(join(tmpdir(), "wirebuddy-package-"));
// A home of its own: npm's cache and config, WireBuddy's data folder
const home = join(work, "home");
mkdirSync(home);
const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), npm_config_update_notifier: "false", WIREBUDDY_EXTENSIONS: "" };
const npm = (args, cwd = work) => execFileSync("npm", args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (err) {
    failures++;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}

try {
  const [{ filename, files }] = JSON.parse(npm(["pack", "--json", "--ignore-scripts", "--pack-destination", work, root], root));
  const shipped = files.map((f) => f.path);

  await check("the package holds what WireBuddy reads at run time, and no tests or source maps", () => {
    for (const f of ["dist/server/main.js", "dist/web/index.html", "dist/web/app.js", "dist/web/styles.css", "dist/panel/bridge.js", "dist/panel/base.css", "examples/extensions/http-gallery/extension.json", "README.md", "LICENSE"]) {
      assert.ok(shipped.includes(f), `${f} is missing`);
    }
    assert.deepEqual(shipped.filter((f) => f.startsWith("test/") || f.startsWith("src/") || f.endsWith(".map")), []);
  });

  const prefix = join(work, "prefix");
  npm(["install", "--global", "--prefix", prefix, join(work, filename)]);
  const bin = join(prefix, "bin/wirebuddy");

  await check("the installed command prints its version", () => {
    const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    assert.equal(execFileSync(bin, ["--version"], { env, encoding: "utf8" }).trim(), `wirebuddy ${version}`);
  });

  const client = new Client({ name: "package", version: "0" });
  await client.connect(new StdioClientTransport({ command: bin, args: ["--mcp", "--port", "0"], env, stderr: "ignore" }));
  const tool = async (name, args = {}) => (await client.callTool({ name, arguments: args })).content.map((c) => c.text).join("\n");
  try {
    await check("over MCP: the viewer page and its script are served from the package", async () => {
      const ui = new URL((await tool("viewer_url")).trim());
      const page = await (await fetch(ui)).text();
      const script = /<script[^>]+src="([^"]*app\.js[^"]*)"/.exec(page)?.[1];
      assert.ok(script, page.slice(0, 200));
      const res = await fetch(new URL(script, ui));
      assert.ok(res.ok && (await res.text()).length > 100_000);
    });

    await check("over MCP: a capture opens and the view counts its frames", async () => {
      assert.match(await tool("open_capture", { path: join(root, "test/fixtures/http.pcapng") }), /^Opened .*http\.pcapng: \d+ frames/);
      assert.match(await tool("get_view_state"), /Frames: \d+/);
    });

    await check("over MCP: the panel guide points at the package's own examples", async () => {
      const guide = await tool("extensions", { action: "guide", topic: "panel" });
      const folder = /Examples to copy with your file tools: (\S+)\/\{/.exec(guide)?.[1];
      assert.ok(folder?.startsWith(prefix), folder);
      assert.ok(existsSync(join(folder, "http-gallery/extension.json")));
      assert.deepEqual(readdirSync(folder).filter((n) => !n.endsWith(".md")).sort(), ["http-gallery", "lidar-wbpc", "rtp-video"]);
    });
  } finally {
    await client.close();
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
