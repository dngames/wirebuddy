// Finds the Chrome or Chromium the browser checks run in: CHROME=<path>, else one on PATH.

import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";

function executable(path) {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function findChrome() {
  if (process.env.CHROME) return executable(process.env.CHROME) ? process.env.CHROME : null;
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    for (const dir of (process.env.PATH ?? "").split(delimiter)) {
      if (dir && executable(join(dir, name))) return join(dir, name);
    }
  }
  return null;
}

/** Chrome's path; without one, null after saying so. In CI, where the checks must run, that fails instead. */
export function chromeOrSkip() {
  const chrome = findChrome();
  if (chrome) return chrome;
  const why = "no Chrome or Chromium found (set CHROME to its path)";
  if (process.env.CI) {
    console.error(`FAIL ${why}`);
    process.exit(1);
  }
  console.log(`skipped: ${why}`);
  return null;
}
