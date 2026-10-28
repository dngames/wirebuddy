/**
 * FlowIndex: the flow of each packet of a growing capture, from the packets'
 * first bytes. A slice of the newest packets brings along what Wireshark needs
 * to read them as it reads the whole file: the first packets of their flows
 * (TCP handshake and window scaling, TLS handshake), each flow's packets just
 * before the slice from the other side's last message on (a response under way
 * is read from its request), and a TCP flow's packets after the slice until
 * the data under way at the chunk's end is complete (it is "reassembled in" a
 * later packet). A flow is an IP protocol, its address and port pair and VLAN
 * ids; a TCP SYN after other packets starts a new one, which follows on from
 * the old one (Wireshark tells port reuse by it). It keeps 17 bytes a packet.
 */

import { parse, Parsed, type Link } from "./layers.ts";

/** Packets kept from the start of each flow. */
export const HEAD_FRAMES = 16;
/** Bytes of each packet the index reads. */
export const HEAD_BYTES = 128;
/** Flows kept; beyond this a quarter is forgotten, ended ones and the longest idle first. */
const MAX_FLOWS = 200_000;
/** Packets walked back per flow for its last packet the other way. */
const MAX_OTHER_WAY = 1000;

/** How much a slice may bring along: frames, and bytes as `size` counts them. */
export interface Budget {
  frames: number;
  bytes: number;
  size: (frame: number) => number;
}

interface Flow {
  id: number;
  /** Its first frames. */
  heads: number[];
  /** Its newest frame. */
  last: number;
  /** Its newest frame with payload, and the turn of the run of data it is in (see turnOf). */
  lastData: number;
  turn: number;
  /** Only SYNs so far: a repeated SYN is the same connection. */
  synOnly: boolean;
  tcp: boolean;
  /** A TCP handshake started it; a FIN or RST ended it. */
  handshake: boolean;
  closed: boolean;
}

export class FlowIndex {
  /** Frames fed: 1..count. */
  count = 0;
  /** Per frame: its flow's id, negative in the direction from the higher address; 0 for none. */
  private flowOf = new Int32Array(4096);
  /** Per frame: the previous and the next frame of its flow, 0 for none (yet). */
  private prevOf = new Int32Array(4096);
  private nextOf = new Int32Array(4096);
  /**
   * Per frame: the turn of its flow then, the other side's last frame with
   * payload before the current side's run of data began; 0 for none. Frames
   * of one run of data share it.
   */
  private turnOf = new Int32Array(4096);
  /** Per frame: 1 when it carries UDP or TCP payload. */
  private data = new Uint8Array(4096);
  private readonly byKey = new Map<string, Flow>();
  private readonly byId = new Map<number, Flow>();
  private nextId = 1;
  private readonly parsed = new Parsed();

  /** Adds the next frame (count + 1) with its first bytes. */
  feed(frame: number, link: Link, data: Uint8Array): void {
    if (frame !== this.count + 1) throw new Error(`frame ${frame} fed after ${this.count}`);
    if (frame > this.flowOf.length) {
      this.flowOf = grown(this.flowOf);
      this.prevOf = grown(this.prevOf);
      this.nextOf = grown(this.nextOf);
      this.turnOf = grown(this.turnOf);
      const more = new Uint8Array(this.data.length * 2);
      more.set(this.data);
      this.data = more;
    }
    this.count = frame;
    const p = parse(data, link, this.parsed);
    if (!p.ip) return;
    const payload = p.payloadEnd > p.payloadStart;
    this.data[frame - 1] = payload ? 1 : 0;
    const n = p.ip === 4 ? 4 : 16;
    const bytes = Buffer.from(data.buffer, data.byteOffset, data.length);
    const a = `${bytes.toString("latin1", p.src, p.src + n)}:${p.srcport}`;
    const b = `${bytes.toString("latin1", p.dst, p.dst + n)}:${p.dstport}`;
    const forward = a <= b;
    const key = `${p.proto}|${p.vlans.join(".")}|${forward ? a : b}|${forward ? b : a}`;
    const syn = p.tcpFlags >= 0 && (p.tcpFlags & 0x12) === 0x02;
    let flow = this.byKey.get(key);
    if (!flow || (syn && !flow.synOnly)) {
      flow = { id: this.nextId++, heads: [], last: flow?.last ?? 0, lastData: 0, turn: 0, synOnly: syn, tcp: p.proto === 6, handshake: syn, closed: false };
      this.byKey.set(key, flow);
      this.byId.set(flow.id, flow);
    } else if (!syn) flow.synOnly = false;
    if (p.tcpFlags >= 0 && p.tcpFlags & 0x05) flow.closed = true;
    if (flow.heads.length < HEAD_FRAMES) flow.heads.push(frame);
    const id = forward ? flow.id : -flow.id;
    this.flowOf[frame - 1] = id;
    this.prevOf[frame - 1] = flow.last;
    if (flow.last) this.nextOf[flow.last - 1] = frame;
    if (payload) {
      // The other side sent last: a run of data starts here
      if (flow.lastData && this.flowOf[flow.lastData - 1] !== id) flow.turn = flow.lastData;
      flow.lastData = frame;
    }
    this.turnOf[frame - 1] = flow.turn;
    flow.last = frame;
    if (this.byId.size > MAX_FLOWS) this.evict();
  }

  /**
   * Frames before `c0` that the frames c0..to need, ascending, within
   * `budget`. First frame 1 (the time reference) and each flow's last packet
   * before c0 each way, then the flows' first packets, then for each flow its
   * packets before c0 from the other side's last message on (a request and
   * its response so far; a flow without one from its start), whole or not
   * at all, the shortest first.
   */
  context(c0: number, to: number, budget: Budget): Int32Array {
    const out = new Taken(budget);
    if (c0 > 1) out.add(1);
    const seen = new Set<number>();
    /** Per flow, its last frame before c0. */
    const lasts: number[] = [];
    for (let f = c0; f <= Math.min(to, this.count); f++) {
      const id = Math.abs(this.flowOf[f - 1]);
      if (!id || seen.has(id)) continue;
      seen.add(id);
      let p = this.prevOf[f - 1];
      // An older instance of the flow (port reuse) may have packets after c0
      while (p >= c0) p = this.prevOf[p - 1];
      if (p > 0) lasts.push(p);
    }
    // Both directions: TCP analysis follows each side's sequence and acknowledgment numbers
    for (const p of lasts) {
      out.add(p);
      for (let q = this.prevOf[p - 1], steps = 0; q > 0 && steps < MAX_OTHER_WAY; q = this.prevOf[q - 1], steps++) {
        if (Math.sign(this.flowOf[q - 1]) === Math.sign(this.flowOf[p - 1])) continue;
        out.add(q);
        break;
      }
    }
    for (const id of seen) {
      for (const h of this.byId.get(id)?.heads ?? []) if (h < c0 && !out.add(h)) break;
    }
    const runs: number[][] = [];
    for (const p of lasts) {
      const from = this.messageStart(p);
      if (!from) continue;
      const run: number[] = [];
      let q = p;
      for (; q >= from && run.length <= budget.frames; q = this.prevOf[q - 1]) run.push(q);
      if (q < from) runs.push(run);
    }
    runs.sort((x, y) => x.length - y.length);
    for (const run of runs) out.addAll(run);
    return out.sorted();
  }

  /**
   * Frames after `hi` that complete what the TCP flows were sending at the
   * end of chunk lo..end: of each flow whose run of data in the chunk goes on
   * past hi, its packets until its last one with data before the other side
   * sends, within `budget`. `open`: such a run still goes on in the file
   * indexed so far (more may come).
   */
  after(lo: number, end: number, hi: number, budget: Budget): { frames: Int32Array; open: boolean } {
    const out = new Taken(budget);
    /** Per flow with data in the chunk: its last frame with data there, then its last frame up to hi. */
    const data = new Map<number, number>();
    const last = new Map<number, number>();
    for (let f = lo; f <= Math.min(hi, this.count); f++) {
      const id = Math.abs(this.flowOf[f - 1]);
      if (!id) continue;
      if (f <= end && this.data[f - 1] && this.byId.get(id)?.tcp) data.set(id, f);
      if (data.has(id)) last.set(id, f);
    }
    let open = false;
    for (const [id, d] of data) {
      const turn = this.turnOf[d - 1];
      const run: number[] = [];
      let sent = 0;
      let x = this.nextOf[last.get(id)! - 1];
      for (; x && Math.abs(this.flowOf[x - 1]) === id && this.turnOf[x - 1] === turn && run.length < budget.frames; x = this.nextOf[x - 1]) {
        run.push(x);
        if (this.data[x - 1]) sent = run.length;
      }
      if (!sent) continue;
      const all = out.addAll(run.slice(0, sent), true);
      // Up to the newest packet without the other side's turn: the data may go on
      if (all && !x) open = true;
    }
    return { frames: out.sorted(), open };
  }

  /** The first frame of the flow `frame` belongs to, or null when unknown. */
  firstOf(frame: number): number | null {
    if (frame < 1 || frame > this.count) return null;
    return this.byId.get(Math.abs(this.flowOf[frame - 1]))?.heads[0] ?? null;
  }

  /**
   * Where the messages under way at `p` start: right after the current
   * side's run of data before the other side's last one; the flow's start
   * when there is none. 0 when unknown.
   */
  private messageStart(p: number): number {
    const turn = this.turnOf[p - 1];
    const before = turn && this.turnOf[turn - 1];
    return (before && this.nextOf[before - 1]) || this.firstOf(turn || p) || 0;
  }

  /** Forgets a quarter of the flows: ended ones and those without a TCP handshake first, the longest idle first. */
  private evict(): void {
    const live = (f: Flow): number => (f.handshake && !f.closed ? 1 : 0);
    const flows = [...this.byId.values()].sort((x, y) => live(x) - live(y) || x.last - y.last);
    for (const f of flows.slice(0, flows.length >> 2)) this.byId.delete(f.id);
    for (const [key, f] of this.byKey) if (!this.byId.has(f.id)) this.byKey.delete(key);
  }
}

/** Frames taken into a slice, within a budget. */
class Taken {
  private readonly frames = new Set<number>();
  private bytes = 0;

  constructor(private readonly budget: Budget) {}

  /** Takes `frame` if it fits; true when it is taken. */
  add(frame: number): boolean {
    if (this.frames.has(frame)) return true;
    const size = this.budget.size(frame);
    if (this.frames.size >= this.budget.frames || this.bytes + size > this.budget.bytes) return false;
    this.frames.add(frame);
    this.bytes += size;
    return true;
  }

  /** Takes all of `frames` if they fit (with `partly`, as many as fit, in order); true when all are taken. */
  addAll(frames: number[], partly = false): boolean {
    const fresh = frames.filter((f) => !this.frames.has(f));
    const size = fresh.reduce((n, f) => n + this.budget.size(f), 0);
    if (!partly && (this.frames.size + fresh.length > this.budget.frames || this.bytes + size > this.budget.bytes)) return false;
    for (const f of fresh) if (!this.add(f)) return false;
    return true;
  }

  sorted(): Int32Array {
    return Int32Array.from(this.frames).sort();
  }
}

function grown(a: Int32Array<ArrayBuffer>): Int32Array<ArrayBuffer> {
  const b = new Int32Array(a.length * 2);
  b.set(a);
  return b;
}
