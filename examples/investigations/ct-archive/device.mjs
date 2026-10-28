#!/usr/bin/env node
// Emulated image archive (see CONFORMANCE.md): a DICOM storage SCP for CT images that keeps what it
// receives in memory, by SOP Instance UID, and logs each association and the series it stored.
// Usage: node device.mjs [--port 11112]
import { createServer } from "node:net";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { port: { type: "string", default: "11112" } } });
const HOST = "127.0.0.1";
const PORT = Number(values.port);

const AE_TITLE = "ARCHIVE";
const MAX_PDU = 16384;
/** Other PDUs are short: a longer one is no DICOM peer. */
const MAX_OTHER_PDU = 65536;
const IMPLEMENTATION_UID = "2.25.148319916397976774951993427761131673038";
const IMPLEMENTATION_VERSION = "ARCHIVE_4_2";
const APPLICATION_CONTEXT = "1.2.840.10008.3.1.1.1";
const CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2";
const VERIFICATION = "1.2.840.10008.1.1";
const SOP_CLASS_NAME = { [CT_IMAGE_STORAGE]: "CT Image Storage", [VERIFICATION]: "Verification" };
const EXPLICIT = "1.2.840.10008.1.2.1";
/** In order of preference. */
const SYNTAX_NAME = { [EXPLICIT]: "Explicit VR Little Endian", "1.2.840.10008.1.2": "Implicit VR Little Endian" };
const PDU = { ASSOCIATE_RQ: 0x01, ASSOCIATE_AC: 0x02, ASSOCIATE_RJ: 0x03, DATA: 0x04, RELEASE_RQ: 0x05, RELEASE_RP: 0x06, ABORT: 0x07 };
const COMMAND = { C_STORE_RQ: 0x0001, C_ECHO_RQ: 0x0030 };
const NO_DATASET = 0x0101;
const STATUS = { SUCCESS: 0x0000, SOP_CLASS_NOT_SUPPORTED: 0x0122, UNRECOGNIZED_OPERATION: 0x0211, CANNOT_UNDERSTAND: 0xc000 };
const ABORT_REASON = { 1: "unrecognized PDU", 2: "unexpected PDU", 6: "invalid PDU parameter value" };
const REJECT_REASON = { "1/2": "application context not supported", "1/7": "called AE title not recognized", "2/2": "protocol version not supported" };
const LONG_VRS = new Set(["OB", "OD", "OF", "OL", "OV", "OW", "SQ", "SV", "UC", "UN", "UR", "UT", "UV"]);

/** The archive: stored instances by SOP Instance UID. */
const instances = new Map();

function pdu(type, body) {
  const head = Buffer.alloc(6);
  head[0] = type;
  head.writeUInt32BE(body.length, 2);
  return Buffer.concat([head, body]);
}

function item(type, body) {
  const head = Buffer.alloc(4);
  head[0] = type;
  head.writeUInt16BE(body.length, 2);
  return Buffer.concat([head, body]);
}

function items(b, at) {
  const out = [];
  while (at + 4 <= b.length) {
    const length = b.readUInt16BE(at + 2);
    if (at + 4 + length > b.length) return null;
    out.push({ type: b[at], value: b.subarray(at + 4, at + 4 + length) });
    at += 4 + length;
  }
  return out;
}

const str = (v) => (v ? v.toString("latin1").replace(/[\0 ]+$/, "").trim() : "");
const tagAt = (b, at) => ((b.readUInt16LE(at) << 16) | b.readUInt16LE(at + 2)) >>> 0;

/** Implicit VR Little Endian command elements: [tag, value] to bytes, the group length first. */
function command(fields) {
  const implicit = (tag, value) => {
    const head = Buffer.alloc(8);
    head.writeUInt16LE(tag >>> 16, 0);
    head.writeUInt16LE(tag & 0xffff, 2);
    head.writeUInt32LE(value.length, 4);
    return Buffer.concat([head, value]);
  };
  const body = Buffer.concat(fields.map(([tag, value]) => implicit(tag, value)));
  const length = Buffer.alloc(4);
  length.writeUInt32LE(body.length);
  return Buffer.concat([implicit(0x00000000, length), body]);
}

const us = (n) => Buffer.from([n & 0xff, n >> 8]);
const uid = (s) => Buffer.from(s.length % 2 ? `${s}\0` : s, "latin1");

/**
 * Reads the element at `at`, calling onValue(tag, value) for one of defined length; returns where
 * the next one starts, or -1. Undefined lengths run to their delimiter.
 */
function element(b, at, explicit, onValue) {
  if (at + 8 > b.length) return -1;
  const tag = tagAt(b, at);
  const vr = explicit && tag >>> 16 !== 0xfffe ? b.toString("latin1", at + 4, at + 6) : null;
  let length = vr ? b.readUInt16LE(at + 6) : b.readUInt32LE(at + 4);
  at += 8;
  if (vr && LONG_VRS.has(vr)) {
    if (at + 4 > b.length) return -1;
    length = b.readUInt32LE(at);
    at += 4;
  }
  if (length !== 0xffffffff) {
    if (at + length > b.length) return -1;
    onValue?.(tag, b.subarray(at, at + length));
    return at + length;
  }
  while (at >= 0 && at + 8 <= b.length) {
    const t = tagAt(b, at);
    // Item or sequence delimiter
    if (t === 0xfffee00d || t === 0xfffee0dd) return at + 8;
    at = element(b, at, explicit);
  }
  return -1;
}

/** A dataset's top-level elements by tag, or null if it doesn't parse. */
function readDataset(b, explicit) {
  const out = new Map();
  for (let at = 0; at < b.length; ) {
    at = element(b, at, explicit, (tag, value) => out.set(tag, value));
    if (at < 0) return null;
  }
  return out;
}

let associations = 0;

/** One TCP connection: an association from request to release or abort (PS3.8). */
class Association {
  constructor(socket) {
    this.socket = socket;
    this.id = ++associations;
    this.peer = `${socket.remoteAddress}:${socket.remotePort}`;
    this.state = "idle";
    this.rx = Buffer.alloc(0);
    /** Accepted presentation contexts by ID: {sopClass, explicit}. */
    this.contexts = new Map();
    /** The message being received: its context ID, command fragments and fields, dataset fragments. */
    this.message = null;
    this.stores = 0;
    this.stored = 0;
    this.series = new Set();
    socket.setNoDelay(true);
    socket.on("data", (chunk) => this.onData(chunk));
    socket.on("error", () => {});
    socket.on("close", () => this.end("closed"));
  }

  log(text) {
    console.log(`[${this.id}] ${text}`);
  }

  onData(chunk) {
    this.rx = this.rx.length ? Buffer.concat([this.rx, chunk]) : chunk;
    while (this.rx.length >= 6 && this.state !== "done") {
      const type = this.rx[0];
      const length = this.rx.readUInt32BE(2);
      if (length > (type === PDU.DATA ? MAX_PDU : MAX_OTHER_PDU)) return this.abort(6);
      if (this.rx.length < 6 + length) return;
      const body = this.rx.subarray(6, 6 + length);
      this.rx = this.rx.subarray(6 + length);
      this.onPdu(type, body);
    }
  }

  onPdu(type, body) {
    const open = this.state === "open";
    switch (type) {
      case PDU.ASSOCIATE_RQ:
        return this.state === "idle" ? this.associate(body) : this.abort(2);
      case PDU.DATA:
        return open ? this.data(body) : this.abort(2);
      case PDU.RELEASE_RQ:
        if (!open) return this.abort(2);
        this.socket.end(pdu(PDU.RELEASE_RP, Buffer.alloc(4)));
        return this.end("released");
      case PDU.ABORT:
        this.socket.destroy();
        return this.end(`aborted by the caller (source ${body[2]}, reason ${body[3]})`);
      default:
        return this.abort(type >= PDU.ASSOCIATE_AC && type <= PDU.RELEASE_RP ? 2 : 1);
    }
  }

  associate(body) {
    const list = body.length >= 68 ? items(body, 68) : null;
    if (!list) return this.abort(6);
    const called = str(body.subarray(4, 20));
    this.calling = str(body.subarray(20, 36)) || "?";
    const context = str(list.find((i) => i.type === 0x10)?.value);
    let reject = null;
    if (!(body.readUInt16BE(0) & 1)) reject = [2, 2];
    else if (called !== AE_TITLE) reject = [1, 7];
    else if (context !== APPLICATION_CONTEXT) reject = [1, 2];
    if (reject) {
      this.socket.end(pdu(PDU.ASSOCIATE_RJ, Buffer.from([0, 1, ...reject])));
      this.state = "done";
      return this.log(`${this.calling} at ${this.peer}: association rejected, ${REJECT_REASON[reject.join("/")]}${reject[1] === 7 ? ` ("${called}")` : ""}`);
    }
    const answers = [];
    for (const { type, value } of list) {
      if (type !== 0x20 || value.length < 4) continue;
      const sub = items(value, 4) ?? [];
      const sopClass = str(sub.find((s) => s.type === 0x30)?.value);
      const offered = sub.filter((s) => s.type === 0x40).map((s) => str(s.value));
      const syntax = Object.keys(SYNTAX_NAME).find((ts) => offered.includes(ts));
      // 0 acceptance, 3 abstract syntax not supported, 4 transfer syntaxes not supported
      const result = !SOP_CLASS_NAME[sopClass] ? 3 : !syntax ? 4 : 0;
      if (result === 0) this.contexts.set(value[0], { sopClass, explicit: syntax === EXPLICIT });
      answers.push(item(0x21, Buffer.concat([Buffer.from([value[0], 0, result, 0]), item(0x40, Buffer.from(syntax ?? EXPLICIT, "latin1"))])));
    }
    const maxLength = Buffer.alloc(4);
    maxLength.writeUInt32BE(MAX_PDU);
    const head = Buffer.from(body.subarray(0, 68));
    head.writeUInt16BE(1, 0);
    this.socket.write(
      pdu(
        PDU.ASSOCIATE_AC,
        Buffer.concat([
          head,
          item(0x10, Buffer.from(APPLICATION_CONTEXT, "latin1")),
          ...answers,
          item(0x50, Buffer.concat([item(0x51, maxLength), item(0x52, Buffer.from(IMPLEMENTATION_UID, "latin1")), item(0x55, Buffer.from(IMPLEMENTATION_VERSION, "latin1"))])),
        ]),
      ),
    );
    this.state = "open";
    const accepted = [...this.contexts.values()].map((c) => `${SOP_CLASS_NAME[c.sopClass]} in ${c.explicit ? "Explicit" : "Implicit"} VR Little Endian`);
    this.log(`${this.calling} at ${this.peer}: association accepted, ${accepted.join(", ") || "no presentation context"}`);
  }

  /** A P-DATA-TF: PDVs put together into messages. */
  data(body) {
    for (let at = 0; at < body.length; ) {
      const length = at + 6 <= body.length ? body.readUInt32BE(at) : 0;
      const id = body[at + 4];
      const control = body[at + 5];
      if (length < 2 || at + 4 + length > body.length || !this.contexts.has(id)) return this.abort(6);
      const fragment = body.subarray(at + 6, at + 4 + length);
      at += 4 + length;
      const m = (this.message ??= { id, command: [], data: [], fields: null });
      // Command, then dataset, all on one presentation context
      if (id !== m.id || (control & 1 ? m.fields : !m.fields)) return this.abort(6);
      if (control & 1) {
        m.command.push(fragment);
        if (!(control & 2)) continue;
        m.fields = readDataset(Buffer.concat(m.command), false);
        if (!m.fields) return this.abort(6);
        if (m.fields.get(0x00000800)?.readUInt16LE(0) !== NO_DATASET) continue;
      } else {
        m.data.push(fragment);
        if (!(control & 2)) continue;
      }
      this.message = null;
      this.answer(m, Buffer.concat(m.data));
    }
  }

  answer(m, data) {
    const field = m.fields.get(0x00000100)?.readUInt16LE(0);
    const sopClass = str(m.fields.get(0x00000002));
    const sopUid = str(m.fields.get(0x00001000));
    let status = STATUS.UNRECOGNIZED_OPERATION;
    if (field === COMMAND.C_ECHO_RQ) status = STATUS.SUCCESS;
    if (field === COMMAND.C_STORE_RQ) {
      status = this.store(this.contexts.get(m.id), sopClass, sopUid, data);
      this.stores++;
      if (status === STATUS.SUCCESS) this.stored++;
    }
    const fields = [
      [0x00000002, uid(sopClass)],
      [0x00000100, us((field ?? 0) | 0x8000)],
      [0x00000120, m.fields.get(0x00000110) ?? us(0)],
      [0x00000800, us(NO_DATASET)],
      [0x00000900, us(status)],
    ];
    if (field === COMMAND.C_STORE_RQ) fields.push([0x00001000, uid(sopUid)]);
    const rsp = command(fields);
    const header = Buffer.alloc(6);
    header.writeUInt32BE(rsp.length + 2, 0);
    header[4] = m.id;
    header[5] = 3;
    this.socket.write(pdu(PDU.DATA, Buffer.concat([header, rsp])));
  }

  store(context, sopClass, sopUid, data) {
    if (context.sopClass !== CT_IMAGE_STORAGE || sopClass !== CT_IMAGE_STORAGE) return STATUS.SOP_CLASS_NOT_SUPPORTED;
    const ds = readDataset(data, context.explicit);
    const series = str(ds?.get(0x0020000e));
    if (!ds || !series || !sopUid || str(ds.get(0x00080018)) !== sopUid) return STATUS.CANNOT_UNDERSTAND;
    // A SOP Instance UID we have is a corrected re-send: it replaces the stored instance
    instances.set(sopUid, { series, number: str(ds.get(0x00200011)), thickness: Number(str(ds.get(0x00180050))), data });
    this.series.add(series);
    return STATUS.SUCCESS;
  }

  abort(reason) {
    this.socket.end(pdu(PDU.ABORT, Buffer.from([0, 0, 2, reason])));
    this.end(`aborted: ${ABORT_REASON[reason]}`);
  }

  /** Logs how the association ended and what the archive now holds of each series it stored to. */
  end(how) {
    if (this.state === "done") return;
    const opened = this.state !== "idle";
    this.state = "done";
    if (!opened) return this.log(`${this.peer}: ${how} before an association`);
    const failed = this.stores - this.stored;
    this.log(`${how} after ${this.stores} C-STORE: ${this.stored} Success${failed ? `, ${failed} failed` : ""}`);
    for (const series of this.series) {
      const held = [...instances.values()].filter((i) => i.series === series);
      this.log(`series ${held[0].number} (${held[0].thickness} mm): ${held.length} instances`);
    }
  }
}

const server = createServer((socket) => new Association(socket));
server.on("error", (err) => {
  console.error(`device: ${err.message}`);
  process.exit(1);
});
server.listen(PORT, HOST, () => console.log(`${AE_TITLE} storage SCP listening on ${HOST}:${PORT}, CT Image Storage, max PDU ${MAX_PDU}`));
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => process.exit(0));
