/**
 * Telling capture files apart: the names the file dialog lists, the check by
 * content that keeps open() to captures, and the first bytes of a file that
 * a growing capture keeps.
 */

import { closeSync, createReadStream, openSync, readSync, statSync } from "node:fs";
import type { Transform } from "node:stream";
import { createGunzip, createZstdDecompress } from "node:zlib";

/** Names the file dialog lists: of the formats looksLikeCapture lets open() read. */
export const CAPTURE_FILE = /\.(pcapng|pcap|cap|ntar|snoop)(\.(gz|zst))?$/i;

/** pcap (both byte orders, µs and ns), pcapng, snoop and Network Monitor 2 files start with these. */
const CAPTURE_MAGIC = ["a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1", "0a0d0d0a", "736e6f6f70000000", "474d4255"];

/**
 * Keeps open() to capture files, by content (also inside gzip and zstd), so it
 * can't be used to read arbitrary files: names prove nothing.
 */
export async function looksLikeCapture(file: string): Promise<boolean> {
  const head = (await firstBytes(file, 8)).toString("hex");
  const inner = head.startsWith("1f8b") ? createGunzip() : head.startsWith("28b52ffd") && typeof createZstdDecompress === "function" ? createZstdDecompress() : null;
  const hex = inner ? (await firstBytes(file, 8, inner)).toString("hex") : head;
  return CAPTURE_MAGIC.some((m) => hex.startsWith(m));
}

/** The first `n` bytes of `file`, through `transform` if given; fewer when it is shorter or broken. */
function firstBytes(file: string, n: number, transform?: Transform): Promise<Buffer> {
  return new Promise((done) => {
    const src = createReadStream(file, transform ? {} : { start: 0, end: n - 1 });
    const out = transform ? src.pipe(transform) : src;
    const chunks: Buffer[] = [];
    let len = 0;
    let finished = false;
    const finish = (): void => {
      if (finished) return;
      finished = true;
      src.destroy();
      transform?.destroy();
      done(Buffer.concat(chunks).subarray(0, n));
    };
    out.on("data", (c: Buffer) => {
      chunks.push(c);
      len += c.length;
      if (len >= n) finish();
    });
    out.on("end", finish);
    out.on("error", finish);
    src.on("error", finish);
  });
}

/** The first bytes of a file: a capture that only grows keeps them. */
export function fileHead(file: string): Buffer {
  let fd = -1;
  try {
    fd = openSync(file, "r");
    const buf = Buffer.alloc(4096);
    return buf.subarray(0, readSync(fd, buf, 0, buf.length, 0));
  } catch {
    return Buffer.alloc(0);
  } finally {
    if (fd >= 0) closeSync(fd);
  }
}

export function safeSize(file: string): number {
  return statSync(file, { throwIfNoEntry: false })?.size ?? -1;
}
