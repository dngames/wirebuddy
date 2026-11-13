// The ACME messages of the guide's TCP template, on TCP port 50000: a 7-byte header (magic 0xACE1, u8 kind,
// u32 body length), then the body. Client 10.0.0.1:52001 sends three messages in one segment (kinds 1, 2, 1;
// bodies of 2, 4 and 0 bytes); client 10.0.0.1:52002 sends one (kind 2, body of 6 bytes) split over two segments.
import { writeFileSync } from "node:fs";
import * as g from "./capgen.mjs";

const message = (kind, body) => {
  const head = Buffer.alloc(7);
  head.writeUInt16BE(0xace1, 0);
  head.writeUInt8(kind, 2);
  head.writeUInt32BE(body.length, 3);
  return Buffer.concat([head, body]);
};

/** Writes the capture to `path`: frame 1 holds three messages, frames 2 and 3 the two parts of the fourth. */
export function writeAcmeTcpCapture(path) {
  const together = Buffer.concat([message(1, Buffer.from([1, 2])), message(2, Buffer.from([3, 4, 5, 6])), message(1, Buffer.alloc(0))]);
  const split = message(2, Buffer.from([7, 8, 9, 10, 11, 12]));
  const segments = [
    [52001, together],
    [52002, split.subarray(0, 10)],
    [52002, split.subarray(10)],
  ];
  const seq = new Map();
  const records = segments.map(([sport, payload], i) => {
    const at = seq.get(sport) ?? 1000;
    seq.set(sport, at + payload.length);
    return g.pcapRecord(1700000000, i * 1000, g.eth(0x0800, g.ip4(6, g.tcp(sport, 50000, payload, { seq: at }))));
  });
  writeFileSync(path, Buffer.concat([g.pcapHeader(), ...records]));
}
