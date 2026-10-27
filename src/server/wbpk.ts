/**
 * WBPK, the binary page of packets panels get, little-endian:
 *   u32 magic "WBPK", u32 header bytes h, header JSON padded with spaces to a multiple of 8,
 *   f64 times[n], u32 frames[n], u32 lens[n], u32 offsets[n + 1], u8 dirs[n] (with "dirs"), u8 data.
 * `offsets` index `data`: packet i's bytes are data[offsets[i], offsets[i + 1]).
 */

export const WBPK_MAGIC = 0x4b504257;

export interface PageRow {
  frame: number;
  /** Epoch seconds, NaN when unknown. */
  time: number;
  /** Length on the wire. */
  len: number;
  data: Uint8Array;
  /** Follow chunks: 1 from the server, 0 from the client. */
  dir?: number;
}

export function encodePage(header: Record<string, unknown>, rows: PageRow[], dirs = false): Buffer {
  const n = rows.length;
  const json = Buffer.from(JSON.stringify({ v: 1, ...header, n, dirs }));
  const h = Math.ceil(json.length / 8) * 8;
  let dataLen = 0;
  for (const r of rows) dataLen += r.data.length;
  const start = 8 + h;
  const buf = Buffer.alloc(start + n * 20 + 4 + (dirs ? n : 0) + dataLen, 0x20, "latin1");
  buf.writeUInt32LE(WBPK_MAGIC, 0);
  buf.writeUInt32LE(h, 4);
  json.copy(buf, 8);
  let at = start;
  for (const r of rows) at = buf.writeDoubleLE(r.time, at);
  for (const r of rows) at = buf.writeUInt32LE(r.frame, at);
  for (const r of rows) at = buf.writeUInt32LE(r.len >>> 0, at);
  let offset = 0;
  for (const r of rows) {
    at = buf.writeUInt32LE(offset, at);
    offset += r.data.length;
  }
  at = buf.writeUInt32LE(offset, at);
  if (dirs) for (const r of rows) buf[at++] = r.dir ?? 0;
  for (const r of rows) {
    buf.set(r.data, at);
    at += r.data.length;
  }
  return buf;
}
