/**
 * FrameStore: raw packets read straight from the open file, without sharkd,
 * for panels and the live view's slices, when it is an uncompressed pcap or
 * pcapng file. It keeps only where
 * each record starts (8 bytes a packet); times, lengths and bytes are read
 * with the record. Indexing stops at the first incomplete or broken block and
 * looks there again when the file grows. Nothing in the file is trusted: no
 * record is read past its block, and none is longer than MAX_RECORD.
 */

import { closeSync, openSync, readSync, statSync } from "node:fs";
import { open, stat, type FileHandle } from "node:fs/promises";
import { linkOfType, type Link } from "./layers.ts";

/** Longest record (packet bytes) it reads. */
export const MAX_RECORD = 16 * 1024 * 1024;
/** Longest pcapng block: a record and its options. */
const MAX_BLOCK = MAX_RECORD + 64 * 1024;
/** Read at once while indexing; also the longest block other than a record. */
const CHUNK = 1024 * 1024;
/** Records read at once, and how far apart they may be for that. */
const SPAN = 4 * 1024 * 1024;
const GAP = 64 * 1024;
/** First bytes kept: other first bytes are another file. */
const HEAD = 4096;
const EMPTY = new Uint8Array(0);

const SHB = 0x0a0d0d0a;
const IDB = 1;
const OPB = 2;
const SPB = 3;
const ISB = 5;
const EPB = 6;

/** A record: time in epoch seconds (NaN unknown), length on the wire, captured bytes (a view of its own read). */
export type Each = (frame: number, time: number, len: number, link: Link, data: Uint8Array) => void;

interface Iface {
  link: Link;
  snaplen: number;
  /** Timestamp units a second, also as a bigint; seconds added (if_tsoffset). */
  unit: number;
  big: bigint;
  offset: number;
}

interface Section {
  start: number;
  little: boolean;
  ifaces: Iface[];
}

export class FrameStore {
  /** Records indexed: frames 1..count. */
  count = 0;
  /** Why it can't read this file, or null. */
  off: string | null = null;
  /** The file was replaced or cut after it was indexed. */
  changed = false;
  private offsets = new Float64Array(4096);
  /** Each record's block length: a read never reaches past it into other blocks. */
  private sizes = new Uint32Array(4096);
  /** After the last whole record or block: indexing goes on here. */
  private end = 0;
  private fh: FileHandle | null = null;
  private ino = -1;
  private head: Buffer | null = null;
  private format: "pcap" | "pcapng" | null = null;
  /** pcap: byte order, nanosecond timestamps, link type. */
  private little = true;
  private nano = false;
  private link: Link = null;
  private readonly sections: Section[] = [];
  /** The file's size when indexing ran into a block that isn't one: it looks again once the file grew. */
  private stuckAt = -1;
  /** A block other than a record or interface statistics came after the first record. */
  private lateBlocks = false;
  private running: Promise<void> | null = null;
  private next: Promise<void> | null = null;
  /** Reads in flight: the file closes after them. */
  private users = 0;
  private closed = false;
  private readonly scratch = Buffer.allocUnsafe(CHUNK);

  constructor(readonly file: string) {}

  /** Indexes what the file gained since the last update. */
  update(): Promise<void> {
    if (this.running) {
      // One more pass after the running one: the file may have grown since it looked
      this.next ??= this.running
        .catch(() => {})
        .then(() => {
          this.next = null;
          return this.update();
        });
      return this.next;
    }
    this.running = this.use(() => this.index()).finally(() => (this.running = null));
    return this.running;
  }

  /** Whether the file is still the one indexed (same inode, first bytes, not shorter). */
  same(): boolean {
    if (this.changed) return false;
    let fd = -1;
    try {
      const st = statSync(this.file);
      if ((this.ino >= 0 && st.ino !== this.ino) || st.size < this.end) return false;
      if (!this.head?.length) return true;
      fd = openSync(this.file, "r");
      const now = Buffer.alloc(this.head.length);
      return readSync(fd, now, 0, now.length, 0) === now.length && now.equals(this.head);
    } catch {
      return false;
    } finally {
      if (fd >= 0) closeSync(fd);
    }
  }

  close(): void {
    this.closed = true;
    if (!this.users) this.release();
  }

  /** Calls `each` for frames first..last, in order. */
  readRange(first: number, last: number, each: Each): Promise<void> {
    return this.read(Math.max(0, last - first + 1), (i) => first + i, each);
  }

  /** Calls `each` for the given frames (ascending, 1..count), in order. */
  readFrames(frames: ArrayLike<number>, each: Each): Promise<void> {
    return this.read(frames.length, (i) => frames[i], each);
  }

  /** Like readRange, with at most the first `n` bytes of each packet. */
  readHeads(first: number, last: number, n: number, each: Each): Promise<void> {
    return this.read(Math.max(0, last - first + 1), (i) => first + i, each, n);
  }

  private async read(n: number, frameAt: (i: number) => number, each: Each, head = Infinity): Promise<void> {
    await this.use(async () => {
      for (let i = 0; i < n && this.fh; ) {
        const start = this.offsets[frameAt(i) - 1];
        let stop = this.recordEnd(frameAt(i));
        let j = i;
        while (j + 1 < n) {
          const g = frameAt(j + 1);
          const gEnd = this.recordEnd(g);
          if (gEnd - start > SPAN || this.offsets[g - 1] - stop > GAP) break;
          stop = gEnd;
          j++;
        }
        const buf = Buffer.allocUnsafe(stop - start);
        const { bytesRead } = await this.fh.read(buf, 0, buf.length, start);
        const got = buf.subarray(0, bytesRead);
        for (let k = i; k <= j; k++) this.record(got, start, frameAt(k), each, head);
        i = j + 1;
      }
    });
  }

  /** Why the file can't be cut into slices for sharkd, or null. */
  sliceable(): string | null {
    if (this.off) return this.off;
    if (this.changed) return "it changed";
    if (this.sections.length > 1) return "it has several sections";
    if (this.lateBlocks) return "it has interface or other blocks after its first packet";
    return null;
  }

  /**
   * Writes a capture file of the given frames (ascending, 1..count) to `path`,
   * readable only by the user: the file's header (pcapng: the blocks before
   * the first record), then the frames' records as they are in the file.
   */
  async writeSlice(frames: ArrayLike<number>, path: string): Promise<void> {
    const n = frames.length;
    if (!n || frames[0] < 1 || frames[n - 1] > this.count) throw new Error("no such frames");
    const done = await this.use(async () => {
      const out = await open(path, "wx", 0o600);
      try {
        const copy = async (start: number, stop: number): Promise<void> => {
          for (let at = start; at < stop; at += SPAN) {
            const buf = Buffer.allocUnsafe(Math.min(SPAN, stop - at));
            const { bytesRead } = await this.fh!.read(buf, 0, buf.length, at);
            if (bytesRead !== buf.length) throw new Error("the file is shorter than indexed");
            await out.write(buf);
          }
        };
        await copy(0, this.offsets[0]);
        for (let i = 0; i < n; ) {
          const start = this.offsets[frames[i] - 1];
          let stop = this.recordEnd(frames[i]);
          let j = i;
          // Records next to each other in the file go in one piece
          while (j + 1 < n && this.offsets[frames[j + 1] - 1] === stop && this.recordEnd(frames[j + 1]) - start <= SPAN) stop = this.recordEnd(frames[++j]);
          await copy(start, stop);
          i = j + 1;
        }
        return true;
      } finally {
        await out.close();
      }
    });
    if (!done) throw new Error("the capture file is closed");
  }

  /** Bytes of the file from the record of `first` to the end of the one of `last` (1..count). */
  bytes(first: number, last: number): number {
    return this.recordEnd(last) - this.offsets[first - 1];
  }

  /** Bytes of the record of `frame` (1..count). */
  size(frame: number): number {
    return this.sizes[frame - 1];
  }

  /** Where the record's block ends: other blocks between two records are not read with it. */
  private recordEnd(frame: number): number {
    return this.offsets[frame - 1] + this.sizes[frame - 1];
  }

  /** Whether some interface has a link type the layer parser doesn't know (raw matches find nothing there). */
  unknownLinks(): boolean {
    return this.format === "pcap" ? this.link === null : this.sections.some((s) => s.ifaces.some((i) => i.link === null));
  }

  /** Reads the record of `frame` from `buf` (the file from `base` on), at most `head` bytes of the packet. */
  private record(buf: Buffer, base: number, frame: number, each: Each, head = Infinity): void {
    const p = this.offsets[frame - 1] - base;
    if (this.format === "pcap") {
      if (p + 16 > buf.length) return each(frame, NaN, 0, this.link, EMPTY);
      const u32 = (i: number): number => (this.little ? buf.readUInt32LE(i) : buf.readUInt32BE(i));
      const time = u32(p) + u32(p + 4) / (this.nano ? 1e9 : 1e6);
      const cap = Math.min(u32(p + 8), buf.length - p - 16, head);
      return each(frame, time, u32(p + 12), this.link, buf.subarray(p + 16, p + 16 + cap));
    }
    const section = this.sectionAt(base + p);
    if (!section || p + 16 > buf.length) return each(frame, NaN, 0, null, EMPTY);
    const little = section.little;
    const u32 = (i: number): number => (little ? buf.readUInt32LE(i) : buf.readUInt32BE(i));
    const type = u32(p);
    const blockLen = u32(p + 4);
    if (type === SPB) {
      const iface = section.ifaces[0];
      const orig = u32(p + 8);
      const cap = Math.max(0, Math.min(orig, blockLen - 16, iface?.snaplen || Infinity, buf.length - p - 12, head));
      return each(frame, NaN, orig, iface?.link ?? null, buf.subarray(p + 12, p + 12 + cap));
    }
    if (p + 28 > buf.length) return each(frame, NaN, 0, null, EMPTY);
    const iface = section.ifaces[type === OPB ? (little ? buf.readUInt16LE(p + 8) : buf.readUInt16BE(p + 8)) : u32(p + 8)];
    const time = iface ? ifaceTime(iface, u32(p + 12), u32(p + 16)) : NaN;
    const cap = Math.max(0, Math.min(u32(p + 20), blockLen - 32, buf.length - p - 28, head));
    each(frame, time, u32(p + 24), iface?.link ?? null, buf.subarray(p + 28, p + 28 + cap));
  }

  private sectionAt(offset: number): Section | null {
    let lo = 0;
    let hi = this.sections.length - 1;
    let found: Section | null = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (this.sections[mid].start <= offset) {
        found = this.sections[mid];
        lo = mid + 1;
      } else hi = mid - 1;
    }
    return found;
  }

  /** Runs `fn` with the file open; a close meanwhile waits for it. */
  private async use<T>(fn: () => Promise<T>): Promise<T | undefined> {
    if (this.closed) return undefined;
    this.users++;
    try {
      if (!this.fh) {
        const fh = await open(this.file, "r");
        // Another call may have opened it meanwhile
        if (this.fh || this.closed) await fh.close();
        else this.fh = fh;
      }
      return this.closed ? undefined : await fn();
    } finally {
      if (!--this.users && this.closed) this.release();
    }
  }

  private release(): void {
    this.fh?.close().catch(() => {});
    this.fh = null;
  }

  private async index(): Promise<void> {
    if (this.off || this.changed || !this.fh) return;
    const fh = this.fh;
    const [st, path] = await Promise.all([fh.stat(), stat(this.file).catch(() => null)]);
    if (this.ino < 0) this.ino = st.ino;
    // Another file at the path, or this one cut: the records are not where they were
    if (!path || path.ino !== this.ino || st.size < this.end) {
      this.changed = true;
      return;
    }
    const size = st.size;
    if (size === this.stuckAt) return;
    if ((this.head?.length ?? 0) < Math.min(size, HEAD)) {
      const head = await this.readAt(fh, 0, Math.min(size, HEAD));
      if (!head) return;
      this.head = Buffer.from(head);
    }
    if (!this.format && !this.detect(size)) return;
    if (this.format === "pcap") await this.indexPcap(fh, size);
    else await this.indexPcapng(fh, size);
  }

  /** Recognizes the format by the first bytes; false while there are too few, or for another format. */
  private detect(size: number): boolean {
    const h = this.head;
    if (!h || h.length < 4) return false;
    const magic = h.readUInt32BE(0);
    if (magic === SHB) {
      this.format = "pcapng";
      return true;
    }
    const pcap = [0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].indexOf(magic);
    if (pcap < 0) {
      const compressed = ["1f8b", "28b52ffd", "04224d18", "fd377a58", "425a68"].some((m) => h.toString("hex").startsWith(m));
      this.off = compressed ? "it is compressed" : "it is not a pcap or pcapng file";
      return false;
    }
    if (size < 24 || h.length < 24) return false;
    const little = pcap % 2 === 1;
    // Version 2.4 only: Wireshark reads others (AIX, ...) its own ways
    if ((little ? h.readUInt16LE(4) : h.readUInt16BE(4)) !== 2 || (little ? h.readUInt16LE(6) : h.readUInt16BE(6)) !== 4) {
      this.off = "it is a pcap variant WireBuddy doesn't read itself";
      return false;
    }
    this.format = "pcap";
    this.little = little;
    this.nano = pcap >= 2;
    this.link = linkOfType((this.little ? h.readUInt32LE(20) : h.readUInt32BE(20)) & 0x03ffffff);
    this.end = 24;
    return true;
  }

  private async indexPcap(fh: FileHandle, size: number): Promise<void> {
    let buf: Buffer = this.scratch.subarray(0, 0);
    let base = 0;
    for (let pos = this.end; pos + 16 <= size; ) {
      if (pos < base || pos + 16 > base + buf.length) {
        const got = await this.readAt(fh, pos, Math.min(CHUNK, size - pos));
        if (!got) return;
        [buf, base] = [got, pos];
      }
      const p = pos - base;
      const u32 = (i: number): number => (this.little ? buf.readUInt32LE(i) : buf.readUInt32BE(i));
      const incl = u32(p + 8);
      if (incl > MAX_RECORD) {
        this.stuckAt = size;
        return;
      }
      // Wireshark reads a file whose first records look wrong as another pcap variant (SS990417, Nokia, ...)
      if (this.count < 2 && (u32(p + 4) >= (this.nano ? 1e9 : 1e6) || incl > u32(p + 12) || u32(p + 12) > 128 * 1024 * 1024)) {
        this.off = "its first records look like another pcap variant, which WireBuddy doesn't read itself";
        return;
      }
      // A record still being written: later
      if (pos + 16 + incl > size) return;
      this.push(pos, 16 + incl);
      pos += 16 + incl;
      this.end = pos;
    }
  }

  private async indexPcapng(fh: FileHandle, size: number): Promise<void> {
    let buf: Buffer = this.scratch.subarray(0, 0);
    let base = 0;
    const stuck = (): void => {
      this.stuckAt = size;
    };
    for (let pos = this.end; pos + 12 <= size; ) {
      if (pos < base || pos + 12 > base + buf.length) {
        const got = await this.readAt(fh, pos, Math.min(CHUNK, size - pos));
        if (!got) return;
        [buf, base] = [got, pos];
      }
      let p = pos - base;
      let little: boolean;
      if (buf.readUInt32LE(p) === SHB) {
        const bom = buf.readUInt32LE(p + 8);
        if (bom !== 0x1a2b3c4d && bom !== 0x4d3c2b1a) return stuck();
        little = bom === 0x1a2b3c4d;
      } else {
        // The first block opens a section
        const section = this.sections[this.sections.length - 1];
        if (!section) return stuck();
        little = section.little;
      }
      const len = little ? buf.readUInt32LE(p + 4) : buf.readUInt32BE(p + 4);
      if (len < 12 || len % 4 || len > MAX_BLOCK) return stuck();
      if (pos + len > size) return;
      // The block whole when it fits a chunk, else its start
      if (pos + Math.min(len, CHUNK) > base + buf.length) {
        const got = await this.readAt(fh, pos, Math.min(CHUNK, size - pos));
        if (!got) return;
        [buf, base, p] = [got, pos, 0];
      }
      const u32 = (i: number): number => (little ? buf.readUInt32LE(i) : buf.readUInt32BE(i));
      const u16 = (i: number): number => (little ? buf.readUInt16LE(i) : buf.readUInt16BE(i));
      let trailer: number;
      if (p + len <= buf.length) trailer = u32(p + len - 4);
      else {
        const t = await this.readAt(fh, pos + len - 4, 4, Buffer.allocUnsafe(4));
        if (!t) return;
        trailer = little ? t.readUInt32LE(0) : t.readUInt32BE(0);
      }
      if (trailer !== len) return stuck();
      const type = u32(p);
      const section = this.sections[this.sections.length - 1];
      if (this.count && type !== EPB && type !== OPB && type !== SPB && type !== ISB) this.lateBlocks = true;
      if (type === SHB) {
        if (len < 28) return stuck();
        this.sections.push({ start: pos, little, ifaces: [] });
      } else if (type === IDB) {
        if (len < 20 || p + len > buf.length) return stuck();
        section.ifaces.push(readIface(buf, p, len, little));
      } else if (type === EPB || type === OPB) {
        if (len < 32) return stuck();
        const iface = type === OPB ? u16(p + 8) : u32(p + 8);
        const cap = u32(p + 20);
        if (iface >= section.ifaces.length || cap > len - 32 || cap > MAX_RECORD) return stuck();
        this.push(pos, len);
      } else if (type === SPB) {
        if (len < 16 || !section.ifaces.length) return stuck();
        this.push(pos, len);
      }
      pos += len;
      this.end = pos;
    }
  }

  /** `n` bytes of the file from `pos`, or null (and `changed`) when it has fewer now. */
  private async readAt(fh: FileHandle, pos: number, n: number, into = this.scratch): Promise<Buffer | null> {
    const { bytesRead } = await fh.read(into, 0, n, pos);
    if (bytesRead === n) return into.subarray(0, n);
    this.changed = true;
    return null;
  }

  private push(offset: number, size: number): void {
    if (this.count === this.offsets.length) {
      const grown = new Float64Array(this.offsets.length * 2);
      grown.set(this.offsets);
      this.offsets = grown;
      const sizes = new Uint32Array(this.sizes.length * 2);
      sizes.set(this.sizes);
      this.sizes = sizes;
    }
    this.sizes[this.count] = size;
    this.offsets[this.count++] = offset;
  }
}

/** An interface description block: link type, snap length, timestamp resolution and offset. */
function readIface(buf: Buffer, p: number, len: number, little: boolean): Iface {
  const u16 = (i: number): number => (little ? buf.readUInt16LE(i) : buf.readUInt16BE(i));
  let resol = 6;
  let offset = 0;
  const stop = p + len - 4;
  for (let o = p + 16; o + 4 <= stop; ) {
    const [code, olen] = [u16(o), u16(o + 2)];
    const v = o + 4;
    if (code === 0 || v + olen > stop) break;
    if (code === 9 && olen >= 1) resol = buf[v];
    else if (code === 14 && olen >= 8) offset = Number(little ? buf.readBigInt64LE(v) : buf.readBigInt64BE(v));
    o = v + ((olen + 3) & ~3);
  }
  // High bit set: a power of two
  const big = resol & 0x80 ? 1n << BigInt(resol & 0x7f) : 10n ** BigInt(resol);
  return { link: linkOfType(u16(p + 8)), snaplen: little ? buf.readUInt32LE(p + 12) : buf.readUInt32BE(p + 12), unit: Number(big), big, offset };
}

/** Epoch seconds of a 64-bit timestamp in the interface's units. */
function ifaceTime(i: Iface, hi: number, lo: number): number {
  // Below 2^53 exact as a number
  if (hi < 0x200000) {
    const ts = hi * 0x100000000 + lo;
    const whole = Math.floor(ts / i.unit);
    return i.offset + whole + (ts - whole * i.unit) / i.unit;
  }
  const ts = (BigInt(hi) << 32n) | BigInt(lo);
  return i.offset + Number(ts / i.big) + Number(ts % i.big) / i.unit;
}
