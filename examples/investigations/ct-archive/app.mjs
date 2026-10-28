#!/usr/bin/env node
// The reconstruction server's DICOM exporter: sends the head protocol's CT series of a scan to the
// archive over one association, one C-STORE at a time, and reports what the archive answered.
// Usage: node app.mjs [--port 11112]
import { realpathSync } from "node:fs";
import { connect } from "node:net";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const ARCHIVE_HOST = "127.0.0.1";
const ARCHIVE_AE = "ARCHIVE";
const OUR_AE = "RECON";

export const UID = {
  applicationContext: "1.2.840.10008.3.1.1.1",
  ctImageStorage: "1.2.840.10008.5.1.4.1.1.2",
  explicitLittleEndian: "1.2.840.10008.1.2.1",
  implicitLittleEndian: "1.2.840.10008.1.2",
};
const SYNTAX_NAME = { [UID.explicitLittleEndian]: "Explicit VR Little Endian", [UID.implicitLittleEndian]: "Implicit VR Little Endian" };
/** A UID under 2.25 made from a UUID (PS3.5 B.2), so no registered root is needed. */
const fromUuid = (uuid) => `2.25.${BigInt(`0x${uuid.replaceAll("-", "")}`)}`;
const IMPLEMENTATION_UID = fromUuid("71c3190e-e897-4907-bf3f-ec19f02cda70");
const IMPLEMENTATION_VERSION = "RECON_EXPORT_3";
/** The longest P-DATA-TF we accept. */
const MAX_PDU = 16384;
export const PDU = { ASSOCIATE_RQ: 0x01, ASSOCIATE_AC: 0x02, ASSOCIATE_RJ: 0x03, DATA: 0x04, RELEASE_RQ: 0x05, RELEASE_RP: 0x06, ABORT: 0x07 };
const C_STORE_RQ = 0x0001;
export const C_STORE_RSP = 0x8001;
const SUCCESS = 0x0000;
const ANSWER_TIMEOUT_MS = 10_000;

/** The scan as the reconstruction server keeps it: patient, study and the series the protocol exports. */
export const SCAN = {
  patientName: "PHANTOM^HEAD",
  patientId: "PHANTOM-0001",
  date: "20261026",
  time: "091500",
  studyUid: fromUuid("e49d7b22-f04c-47db-8d3c-3f3f93b8756d"),
  frameOfReferenceUid: fromUuid("4ce51105-4625-4d28-b23f-734992d060dd"),
  // first: table position of the first image, mm
  series: [
    { number: 2, uid: fromUuid("a24b88a4-3e3b-41a7-ad65-c28e3f7e9c8a"), description: "Head 5.0", thickness: 5, first: 850, count: 24 },
    { number: 3, uid: fromUuid("3758e8a4-d58d-49a0-90c4-44802971388b"), description: "Head 0.625", thickness: 0.625, first: 870, count: 160 },
  ],
};

// --- The images

const SIZE = 128;
const PIXEL_MM = 1.6;
const RESCALE_INTERCEPT = -1024;
/** Table position of the head's centre, mm. */
const HEAD_AT = 880;
/**
 * The head phantom: ellipsoids in mm around the head's centre (x to the left, y to the back, z up),
 * each drawn over the ones before; tilt in radians about the x axis.
 */
const PHANTOM = [
  { hu: 40, at: [0, 0, 0], r: [78, 98, 88] }, // scalp
  { hu: 1000, at: [0, 0, 0], r: [73, 93, 83] }, // skull
  { hu: 32, at: [0, 3, 2], r: [66, 85, 76] }, // brain
  { hu: 12, at: [-30, -80, -32], r: [12, 12, 12] }, // eyes
  { hu: 12, at: [30, -80, -32], r: [12, 12, 12] },
  { hu: -950, at: [0, -72, -38], r: [16, 13, 12] }, // sinus
  { hu: 6, at: [-12, -4, 20], r: [7, 32, 11], tilt: 0.3 }, // ventricles
  { hu: 6, at: [12, -4, 20], r: [7, 32, 11], tilt: 0.3 },
  { hu: 6, at: [0, 4, 10], r: [4, 26, 5], tilt: -0.45 },
  { hu: 6, at: [0, 38, -26], r: [6, 6, 9], tilt: 0.5 },
  { hu: 68, at: [26, 36, 40], r: [9, 9, 9] }, // lesion
];

function hounsfield(x, y, z) {
  let hu = -1000;
  for (const e of PHANTOM) {
    const c = Math.cos(e.tilt ?? 0);
    const s = Math.sin(e.tilt ?? 0);
    const dy = y - e.at[1];
    const dz = z - e.at[2];
    const u = (x - e.at[0]) / e.r[0];
    const v = (dy * c + dz * s) / e.r[1];
    const w = (dz * c - dy * s) / e.r[2];
    if (u * u + v * v + w * w <= 1) hu = e.hu;
  }
  return hu;
}

/** One axial image at table position z, averaged over its thickness: stored values, little-endian int16. */
function pixels(z, thickness, seed) {
  const out = Buffer.alloc(SIZE * SIZE * 2);
  const depth = Math.max(1, Math.round(thickness / 1.25));
  let noise = seed;
  for (let row = 0; row < SIZE; row++) {
    for (let col = 0; col < SIZE; col++) {
      let hu = 0;
      for (let k = 0; k < depth; k++) hu += hounsfield((col - (SIZE - 1) / 2) * PIXEL_MM, (row - (SIZE - 1) / 2) * PIXEL_MM, z - HEAD_AT + ((k + 0.5) / depth - 0.5) * thickness);
      noise = (Math.imul(noise, 1103515245) + 12345) & 0x7fffffff;
      out.writeInt16LE(Math.round(hu / depth) - RESCALE_INTERCEPT + ((noise >>> 16) % 9) - 4, (row * SIZE + col) * 2);
    }
  }
  return out;
}

/** The series' images in instance order: number, table position and pixels. */
export function* slices(series) {
  for (let i = 0; i < series.count; i++) {
    const location = series.first + i * series.thickness;
    yield { instance: i + 1, location, pixels: pixels(location, series.thickness, series.number * 10007 + i) };
  }
}

// --- DICOM encoding

/** A string value padded to even length: UIDs with a NUL, the rest with a space. */
const text = (s, pad = " ") => Buffer.from(s.length % 2 ? s + pad : s, "latin1");
export const uid = (s) => text(s, "\0");
export function us(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
}
function ul(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}

/** An element in Explicit VR Little Endian; tag as 0xggggeeee. */
function element(tag, vr, value) {
  const long = vr === "OW" || vr === "OB";
  const head = Buffer.alloc(long ? 12 : 8);
  head.writeUInt16LE(tag >>> 16, 0);
  head.writeUInt16LE(tag & 0xffff, 2);
  head.write(vr, 4, "latin1");
  if (long) head.writeUInt32LE(value.length, 8);
  else head.writeUInt16LE(value.length, 6);
  return Buffer.concat([head, value]);
}

/** The CT image's dataset in Explicit VR Little Endian, elements in tag order. */
export function dataset(series, slice, sopUid) {
  const corner = ((-(SIZE - 1) / 2) * PIXEL_MM).toFixed(1);
  return Buffer.concat([
    element(0x00080008, "CS", text("ORIGINAL\\PRIMARY\\AXIAL")),
    element(0x00080016, "UI", uid(UID.ctImageStorage)),
    element(0x00080018, "UI", uid(sopUid)),
    element(0x00080020, "DA", text(SCAN.date)),
    element(0x00080030, "TM", text(SCAN.time)),
    element(0x00080060, "CS", text("CT")),
    element(0x0008103e, "LO", text(series.description)),
    element(0x00100010, "PN", text(SCAN.patientName)),
    element(0x00100020, "LO", text(SCAN.patientId)),
    element(0x00180050, "DS", text(String(series.thickness))),
    element(0x00180060, "DS", text("120")),
    element(0x0020000d, "UI", uid(SCAN.studyUid)),
    element(0x0020000e, "UI", uid(series.uid)),
    element(0x00200011, "IS", text(String(series.number))),
    element(0x00200013, "IS", text(String(slice.instance))),
    element(0x00200032, "DS", text(`${corner}\\${corner}\\${slice.location}`)),
    element(0x00200037, "DS", text("1\\0\\0\\0\\1\\0")),
    element(0x00200052, "UI", uid(SCAN.frameOfReferenceUid)),
    element(0x00201041, "DS", text(String(slice.location))),
    element(0x00280002, "US", us(1)),
    element(0x00280004, "CS", text("MONOCHROME2")),
    element(0x00280010, "US", us(SIZE)),
    element(0x00280011, "US", us(SIZE)),
    element(0x00280030, "DS", text(`${PIXEL_MM}\\${PIXEL_MM}`)),
    element(0x00280100, "US", us(16)),
    element(0x00280101, "US", us(16)),
    element(0x00280102, "US", us(15)),
    element(0x00280103, "US", us(1)),
    element(0x00281050, "DS", text("40")),
    element(0x00281051, "DS", text("80")),
    element(0x00281052, "DS", text(String(RESCALE_INTERCEPT))),
    element(0x00281053, "DS", text("1")),
    element(0x7fe00010, "OW", slice.pixels),
  ]);
}

/** A DIMSE command set: Implicit VR Little Endian, its group length first; fields as [tag, value]. */
export function command(fields) {
  const implicit = ([tag, value]) => Buffer.concat([us(tag >>> 16), us(tag & 0xffff), ul(value.length), value]);
  const body = Buffer.concat(fields.map(implicit));
  return Buffer.concat([implicit([0x00000000, ul(body.length)]), body]);
}

/** A command set's elements by tag. */
function readCommand(b) {
  const out = new Map();
  for (let at = 0; at + 8 <= b.length; ) {
    const length = b.readUInt32LE(at + 4);
    out.set(((b.readUInt16LE(at) << 16) | b.readUInt16LE(at + 2)) >>> 0, b.subarray(at + 8, at + 8 + length));
    at += 8 + length;
  }
  return out;
}

export function pdu(type, body) {
  const head = Buffer.alloc(6);
  head[0] = type;
  head.writeUInt32BE(body.length, 2);
  return Buffer.concat([head, body]);
}

export function item(type, body) {
  const head = Buffer.alloc(4);
  head[0] = type;
  head.writeUInt16BE(body.length, 2);
  return Buffer.concat([head, body]);
}

const ascii = (s) => Buffer.from(s, "latin1");

/** Items in a PDU or item body from `at` on: [{type, value}]. */
function items(b, at) {
  const out = [];
  while (at + 4 <= b.length) {
    const length = b.readUInt16BE(at + 2);
    out.push({ type: b[at], value: b.subarray(at + 4, at + 4 + length) });
    at += 4 + length;
  }
  return out;
}

/** The A-ASSOCIATE-RQ: CT Image Storage as presentation context 1, Explicit VR preferred. */
export function associateRq() {
  const head = Buffer.alloc(68);
  head.writeUInt16BE(1, 0);
  head.write(ARCHIVE_AE.padEnd(16), 4, "latin1");
  head.write(OUR_AE.padEnd(16), 20, "latin1");
  const maxLength = Buffer.alloc(4);
  maxLength.writeUInt32BE(MAX_PDU);
  return pdu(
    PDU.ASSOCIATE_RQ,
    Buffer.concat([
      head,
      item(0x10, ascii(UID.applicationContext)),
      item(0x20, Buffer.concat([Buffer.from([1, 0, 0, 0]), item(0x30, ascii(UID.ctImageStorage)), item(0x40, ascii(UID.explicitLittleEndian)), item(0x40, ascii(UID.implicitLittleEndian))])),
      item(0x50, Buffer.concat([item(0x51, maxLength), item(0x52, ascii(IMPLEMENTATION_UID)), item(0x55, ascii(IMPLEMENTATION_VERSION))])),
    ]),
  );
}

/** P-DATA-TF PDUs carrying one command or dataset: one PDV each, as long as the peer takes. */
export function pData(context, isCommand, data, maxPdu) {
  const room = maxPdu - 6;
  const out = [];
  for (let at = 0; at < data.length; at += room) {
    const fragment = data.subarray(at, at + room);
    const header = Buffer.alloc(6);
    header.writeUInt32BE(fragment.length + 2, 0);
    header[4] = context;
    header[5] = (isCommand ? 1 : 0) | (at + room >= data.length ? 2 : 0);
    out.push(pdu(PDU.DATA, Buffer.concat([header, fragment])));
  }
  return out;
}

export function storeRq(messageId, sopUid) {
  return command([
    [0x00000002, uid(UID.ctImageStorage)],
    [0x00000100, us(C_STORE_RQ)],
    [0x00000110, us(messageId)],
    [0x00000700, us(0)],
    [0x00000800, us(0)],
    [0x00001000, uid(sopUid)],
  ]);
}

const REJECTED = { "1/2": "application context not supported", "1/3": "calling AE title not recognized", "1/7": "called AE title not recognized", "2/2": "protocol version not supported" };

/** One association with the archive: PDUs over TCP, a DIMSE message at a time (PS3.7, PS3.8). */
class Association {
  constructor(socket) {
    this.socket = socket;
    this.rx = Buffer.alloc(0);
    this.fragments = [];
    this.events = [];
    this.waiter = null;
    this.error = null;
    this.maxPdu = MAX_PDU;
    socket.on("data", (chunk) => this.onData(chunk));
    socket.on("error", (err) => this.fail(err));
    socket.on("close", () => this.fail(new Error("the archive closed the connection")));
  }

  static async open(host, port) {
    const socket = await new Promise((resolve, reject) => {
      const s = connect({ host, port, noDelay: true }, () => {
        s.off("error", reject);
        resolve(s);
      });
      s.once("error", reject);
    });
    const a = new Association(socket);
    socket.write(associateRq());
    const answer = await a.next();
    if (answer.type === PDU.ASSOCIATE_RJ) {
      const [result, source, reason] = answer.body.subarray(1, 4);
      throw new Error(`${ARCHIVE_AE} rejected the association${result === 2 ? " for now" : ""}: ${REJECTED[`${source}/${reason}`] ?? `source ${source}, reason ${reason}`}`);
    }
    if (answer.type !== PDU.ASSOCIATE_AC) throw new Error(`${ARCHIVE_AE} answered the association request with PDU type ${answer.type}`);
    for (const { type, value } of items(answer.body, 68)) {
      if (type === 0x21 && value[0] === 1) {
        if (value[2] !== 0) throw new Error(`${ARCHIVE_AE} does not take CT Image Storage (result ${value[2]})`);
        a.syntax = items(value, 4).find((s) => s.type === 0x40)?.value.toString("latin1").replace(/\0+$/, "");
      }
      if (type === 0x50) {
        const max = items(value, 0).find((s) => s.type === 0x51);
        if (max?.value.length === 4 && max.value.readUInt32BE(0) > 0) a.maxPdu = Math.min(MAX_PDU, max.value.readUInt32BE(0));
      }
    }
    if (!SYNTAX_NAME[a.syntax]) throw new Error(`${ARCHIVE_AE} accepted no transfer syntax we offered`);
    return a;
  }

  onData(chunk) {
    this.rx = this.rx.length ? Buffer.concat([this.rx, chunk]) : chunk;
    while (this.rx.length >= 6) {
      const length = this.rx.readUInt32BE(2);
      if (this.rx.length < 6 + length) return;
      const type = this.rx[0];
      const body = this.rx.subarray(6, 6 + length);
      this.rx = this.rx.subarray(6 + length);
      if (type !== PDU.DATA) {
        this.emit({ type, body });
        continue;
      }
      for (let at = 0; at + 6 <= body.length; ) {
        const pdv = body.readUInt32BE(at);
        const control = body[at + 5];
        // Responses are command sets only
        if (control & 1) this.fragments.push(body.subarray(at + 6, at + 4 + pdv));
        if ((control & 3) === 3) {
          this.emit({ type, command: readCommand(Buffer.concat(this.fragments)) });
          this.fragments = [];
        }
        at += 4 + pdv;
      }
    }
  }

  emit(event) {
    const w = this.waiter;
    this.waiter = null;
    if (w) w.resolve(event);
    else this.events.push(event);
  }

  fail(err) {
    this.error ??= err;
    const w = this.waiter;
    this.waiter = null;
    w?.reject(err);
  }

  /** The next PDU, or the next complete response. */
  next() {
    if (this.events.length) return Promise.resolve(this.events.shift());
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(new Error(`no answer from ${ARCHIVE_AE} within ${ANSWER_TIMEOUT_MS / 1000} s`)), ANSWER_TIMEOUT_MS);
      const done = (fn) => (v) => {
        clearTimeout(timer);
        fn(v);
      };
      this.waiter = { resolve: done(resolve), reject: done(reject) };
    });
  }

  /** Sends one image and resolves with the archive's status for it. */
  async store(messageId, sopUid, data) {
    // A write per PDU: Wireshark exports no DICOM object whose PDUs share a TCP segment
    for (const p of [...pData(1, true, storeRq(messageId, sopUid), this.maxPdu), ...pData(1, false, data, this.maxPdu)]) this.socket.write(p);
    const answer = await this.next();
    if (answer.type === PDU.ABORT) throw new Error(`${ARCHIVE_AE} aborted the association (source ${answer.body[2]}, reason ${answer.body[3]})`);
    const field = answer.command?.get(0x00000100)?.readUInt16LE(0);
    const status = answer.command?.get(0x00000900);
    if (field !== C_STORE_RSP || answer.command.get(0x00000120)?.readUInt16LE(0) !== messageId || !status) throw new Error(`no C-STORE-RSP to message ${messageId}`);
    return status.readUInt16LE(0);
  }

  async release() {
    this.socket.write(pdu(PDU.RELEASE_RQ, Buffer.alloc(4)));
    const answer = await this.next();
    if (answer.type !== PDU.RELEASE_RP) throw new Error(`${ARCHIVE_AE} did not confirm the release`);
    this.socket.end();
  }
}

const hex = (n) => `0x${n.toString(16).padStart(4, "0").toUpperCase()}`;

async function main() {
  const { values } = parseArgs({ options: { port: { type: "string", default: "11112" } } });
  const port = Number(values.port);
  const archive = await Association.open(ARCHIVE_HOST, port);
  console.log(`association ${OUR_AE} -> ${ARCHIVE_AE} at ${ARCHIVE_HOST}:${port}: CT Image Storage, ${SYNTAX_NAME[archive.syntax]}, max PDU ${archive.maxPdu}`);
  let sent = 0;
  const failed = [];
  for (const series of SCAN.series) {
    let stored = 0;
    for (const slice of slices(series)) {
      // Same slice, same UID: a re-sent series replaces itself in the archive
      const sopUid = `${series.uid}.${Math.round(slice.location)}`; // whole mm: ".05" would be a component with a leading zero
      const status = await archive.store(++sent, sopUid, dataset(series, slice, sopUid));
      if (status === SUCCESS) stored++;
      else failed.push(`series ${series.number} image ${slice.instance}: ${hex(status)}`);
    }
    console.log(`series ${series.number}  ${series.description.padEnd(12)}${String(series.count).padStart(3)} images, ${stored} Success`);
  }
  await archive.release();
  console.log(`${sent} images sent, ${sent - failed.length} Success${failed.length ? `, ${failed.length} failed:\n  ${failed.join("\n  ")}` : ""}`);
  if (failed.length) process.exitCode = 1;
}

// Run, not imported; also through a symlinked path
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((err) => {
    console.error(`app: ${err.message}`);
    process.exit(1);
  });
}
