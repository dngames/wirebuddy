/**
 * FlowIndex: the flow of each packet of a growing capture, from the packets'
 * first bytes. A slice of the newest packets brings along what Wireshark needs
 * to read them as it reads the whole file: the first packets of their flows
 * (TCP handshake and window scaling, TLS handshake), each flow's packets just
 * before the slice from the start of its messages under way (a response under
 * way is read from its request, or from an earlier one when requests were
 * pipelined into it), a TCP flow's packets after the slice until the data
 * either side had under way at the chunk's end is complete (it is
 * "reassembled in" a later packet), and the answers a non-TCP flow of
 * requests and answers still owes (an echo reply after the slice). The other
 * side may send while a message is under way (pipelined requests, a 100
 * Continue before an upload): up to MAX_PIPELINED short runs of its data are
 * not taken for the message's end, unless what follows starts a new message
 * (an HTTP/1 one, a TLS record). A flow is an IP protocol, its address and
 * port pair and VLAN ids; a TCP SYN after other packets starts a new one,
 * which follows on from the old one (Wireshark tells port reuse by it). It
 * keeps 25 bytes a packet.
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
/** Packets of a flow's run a slice may hold already (its first ones, its last one each way). */
const TAKEN_BEFORE = HEAD_FRAMES + 2;
/** Runs of data the other side may send while a message is under way, and their packets with data at most. */
const MAX_PIPELINED = 3;
const MAX_INTERLEAVED = 16;
/** Answers a non-TCP flow is waited for, per side. */
const MAX_ANSWERS = 64;
/** Seconds without a packet from a side after which no more of its message or answers under way come. */
const IDLE = 10;
/** Payload that starts an HTTP/1 message: a status line, a request line. */
const HTTP_START = /^(?:HTTP\/1\.[01] [1-5]\d\d[ \r]|(?:GET|HEAD|POST|PUT|DELETE|OPTIONS|TRACE|PATCH|CONNECT) [!-~])/;
/** Per frame data: payload, payload that starts a message (an HTTP/1 one, a TLS record). */
const PAYLOAD = 1;
const STARTS = 2;

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
  /** A TCP handshake started it; a FIN or RST came. */
  handshake: boolean;
  closed: boolean;
  /** No more data comes from the side with the lower address, and from the other one (its FIN, either side's RST). */
  ended: [boolean, boolean];
  /** Packets so far, and of them from the lower address. */
  n: number;
  forward: number;
  /** Capture time of the newest packet from the lower address, and from the other side, in seconds (NaN unknown); its first packet's for a side that sent none. */
  times: [number, number];
}

/** Where a TCP flow's walk is: the turn, the turns it went past since its side's last data in the chunk, the other side's packets with data in its current run. */
interface Turns {
  turn: number;
  turns: number;
  interleaved: number;
}

/** A TCP flow's walk past hi. */
interface Walk extends Turns {
  id: number;
  /** The side whose data it completes: 1 the lower address, -1 the other. */
  side: number;
  /** The next frame to walk, 0 at the newest one. */
  x: number;
  /** The budget cut it short; it went past all it may up to hi already. */
  cut: boolean;
  done: boolean;
}

export class FlowIndex {
  /** Frames fed: 1..count. */
  count = 0;
  /** Capture time of the newest frame, in seconds (NaN unknown). */
  private time = NaN;
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
  /** Per frame: its flow's packets before it, and of them from the lower address. */
  private ordOf = new Int32Array(4096);
  private forwardOf = new Int32Array(4096);
  /** Per frame: PAYLOAD when it carries UDP or TCP payload, STARTS when that starts a message. */
  private data = new Uint8Array(4096);
  private readonly byKey = new Map<string, Flow>();
  private readonly byId = new Map<number, Flow>();
  private nextId = 1;
  private readonly parsed = new Parsed();

  /** Adds the next frame (count + 1) with its first bytes and its capture time in seconds. */
  feed(frame: number, link: Link, data: Uint8Array, time = NaN): void {
    if (frame !== this.count + 1) throw new Error(`frame ${frame} fed after ${this.count}`);
    if (frame > this.flowOf.length) {
      this.flowOf = grown(this.flowOf);
      this.prevOf = grown(this.prevOf);
      this.nextOf = grown(this.nextOf);
      this.turnOf = grown(this.turnOf);
      this.ordOf = grown(this.ordOf);
      this.forwardOf = grown(this.forwardOf);
      const more = new Uint8Array(this.data.length * 2);
      more.set(this.data);
      this.data = more;
    }
    this.count = frame;
    this.time = time;
    const p = parse(data, link, this.parsed);
    if (!p.ip) return;
    const payload = p.payloadEnd > p.payloadStart;
    const bytes = Buffer.from(data.buffer, data.byteOffset, data.length);
    this.data[frame - 1] = !payload ? 0 : p.proto === 6 && startsMessage(bytes, p.payloadStart, p.payloadEnd) ? STARTS : PAYLOAD;
    const n = p.ip === 4 ? 4 : 16;
    const a = `${bytes.toString("latin1", p.src, p.src + n)}:${p.srcport}`;
    const b = `${bytes.toString("latin1", p.dst, p.dst + n)}:${p.dstport}`;
    const forward = a <= b;
    const key = `${p.proto}|${p.vlans.join(".")}|${forward ? a : b}|${forward ? b : a}`;
    const syn = p.tcpFlags >= 0 && (p.tcpFlags & 0x12) === 0x02;
    let flow = this.byKey.get(key);
    if (!flow || (syn && !flow.synOnly)) {
      flow = { id: this.nextId++, heads: [], last: flow?.last ?? 0, lastData: 0, turn: 0, synOnly: syn, tcp: p.proto === 6, handshake: syn, closed: false, ended: [false, false], n: 0, forward: 0, times: [time, time] };
      this.byKey.set(key, flow);
      this.byId.set(flow.id, flow);
    } else if (!syn) flow.synOnly = false;
    if (p.tcpFlags >= 0 && p.tcpFlags & 0x05) {
      flow.closed = true;
      // A RST ends both sides, a FIN its sender's
      if (p.tcpFlags & 0x04) flow.ended = [true, true];
      else flow.ended[forward ? 0 : 1] = true;
    }
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
    this.ordOf[frame - 1] = flow.n++;
    this.forwardOf[frame - 1] = forward ? flow.forward++ : flow.forward;
    flow.last = frame;
    flow.times[forward ? 0 : 1] = time;
    if (this.byId.size > MAX_FLOWS) this.evict();
  }

  /**
   * Frames before `c0` that the frames c0..to need, ascending, within
   * `budget`. First frame 1, `ref` (what times count from: the first frame,
   * the nearest time reference before c0) and each flow's last packet
   * before c0 each way, then the flows' first packets, then for each flow its
   * packets before c0 from the other side's last message on (a request and
   * its response so far; a flow without one from its start), whole or not
   * at all, the shortest first; then, while they fit, a TCP flow's from up
   * to MAX_PIPELINED exchanges further back, one at a time (a response that
   * requests were pipelined into, an upload after a 100 Continue). It walks
   * no more than about twice the budget's frames, however long the flows.
   */
  context(c0: number, to: number, budget: Budget, ref = 0): Int32Array {
    const out = new Taken(budget);
    if (c0 > 1) out.add(1);
    if (ref > 1 && ref < c0) out.add(ref);
    const seen = new Set<number>();
    /** Per flow, its last frame before c0. */
    const lasts = new Set<number>();
    for (let f = c0; f <= Math.min(to, this.count); f++) {
      const id = Math.abs(this.flowOf[f - 1]);
      if (!id || seen.has(id)) continue;
      seen.add(id);
      let p = this.prevOf[f - 1];
      // An older instance of the flow (port reuse) may have packets after c0
      while (p >= c0) p = this.prevOf[p - 1];
      if (p > 0) lasts.add(p);
    }
    // Both directions: TCP analysis follows each side's sequence and acknowledgment numbers
    for (const p of lasts) {
      out.add(p);
      if (!this.sentBy(p, -Math.sign(this.flowOf[p - 1]))) continue;
      for (let q = this.prevOf[p - 1], steps = 0; q > 0 && steps < MAX_OTHER_WAY; q = this.prevOf[q - 1], steps++) {
        if (Math.sign(this.flowOf[q - 1]) === Math.sign(this.flowOf[p - 1])) continue;
        out.add(q);
        break;
      }
    }
    for (const id of seen) {
      for (const h of this.byId.get(id)?.heads ?? []) if (h < c0 && !out.add(h)) break;
    }
    /** Per flow, the start of its packets taken so far up to its last one before c0 (0: none yet). */
    let runs = [...lasts].map((p) => ({ p, from: 0 }));
    /** Frames walked for runs that didn't fit after all. */
    let wasted = 0;
    for (let back = 1; back <= MAX_PIPELINED + 1; back++) {
      const parts = runs.map((r) => {
        const until = r.from ? this.prevOf[r.from - 1] : r.p;
        const from = this.messageStart(r.p, back);
        // Its length in O(1), so that only runs that fit are walked
        const length = !from || !until || (r.from && from >= r.from) ? 0 : this.ordOf[until - 1] - this.ordOf[from - 1] + 1;
        return { r, from, until, length };
      });
      parts.sort((x, y) => x.length - y.length);
      runs = [];
      for (const { r, from, until, length } of parts) {
        if (!length) {
          if (from) runs.push(r);
          continue;
        }
        if (out.size + length - TAKEN_BEFORE > budget.frames || wasted > budget.frames) break;
        const room = budget.bytes - out.bytes;
        const run: number[] = [];
        let bytes = 0;
        for (let q = until, i = 0; i < length && q > 0 && bytes <= room; q = this.prevOf[q - 1], i++) {
          run.push(q);
          if (!out.has(q)) bytes += budget.size(q);
        }
        if (run.length === length && run[length - 1] === from && out.addAll(run)) runs.push({ p: r.p, from });
        else wasted += run.length;
      }
      runs = runs.filter((r) => this.byId.get(Math.abs(this.flowOf[r.p - 1]))?.tcp);
    }
    return out.sorted();
  }

  /**
   * Frames after `hi` that complete what the flows of chunk lo..end were
   * sending at its end, within `budget`. Of a TCP flow, for each side with
   * data in the chunk: its packets until its last one with data before the
   * other side sends; then, past up to MAX_PIPELINED short runs of the other
   * side's (requests pipelined into a response, a 100 Continue before an
   * upload), until its last one with data before the other side's next,
   * unless its run after them starts a new message (an HTTP/1 one, a TLS
   * record). Of a non-TCP flow of requests and answers: the other side's
   * packets that answer its packets in the chunk (an echo reply, a DNS
   * response). `open`: they may still change, as such a run reaches the
   * newest packet indexed (more may come, unless its side ended or went
   * quiet: see over()), the budget cut short a side's run before the other
   * side sent, or answers are still owed; the flows that leave it open go
   * into `openFlows`. Past the other side's runs a new
   * message may have started instead: those walks go the shortest first, and
   * cutting them short leaves the chunk as it is. It walks no more than about
   * three times the budget's frames, however long the flows.
   */
  after(lo: number, end: number, hi: number, budget: Budget, openFlows = new Set<number>()): { frames: Int32Array; open: boolean } {
    const out = new Taken(budget);
    /** Per flow in the chunk: its first and last frame there and its last frame up to hi; of a TCP flow a walk from each side's last data there. */
    const chunk = new Map<number, { first: number; last: number; upTo: number; tcp: boolean; walks: [Walk | null, Walk | null] }>();
    for (let f = lo; f <= Math.min(hi, this.count); f++) {
      const id = Math.abs(this.flowOf[f - 1]);
      if (!id) continue;
      let c = chunk.get(id);
      if (f <= end) {
        if (!c) chunk.set(id, (c = { first: f, last: f, upTo: f, tcp: !!this.byId.get(id)?.tcp, walks: [null, null] }));
        c.last = f;
        const side = Math.sign(this.flowOf[f - 1]);
        if (this.data[f - 1] && c.tcp) c.walks[side > 0 ? 0 : 1] = { id, side, x: 0, cut: false, done: false, turn: this.turnOf[f - 1], turns: 0, interleaved: 0 };
      }
      if (!c) continue;
      c.upTo = f;
      // Past the turns it may walk already: what its side sent ended before hi
      for (const w of c.walks) if (w && !w.done) w.done = !this.step(w, f, 2 * MAX_PIPELINED);
    }
    const walks: Walk[] = [];
    for (const c of chunk.values()) {
      for (const w of c.walks) {
        if (!w || w.done) continue;
        w.x = this.nextOf[c.upTo - 1];
        walks.push(w);
      }
    }
    // First what each sender was sending at the chunk's end, then the answers owed, then past the other side's
    for (const w of walks) {
      if (w.turns > 0) continue;
      this.walk(w, 0, out);
      if (this.mayChange(w)) openFlows.add(w.id);
    }
    let steps = budget.frames;
    for (const [id, c] of chunk) {
      const flow = this.byId.get(id);
      if (!flow || flow.tcp) continue;
      for (const side of [1, -1]) {
        const owed = this.owed(side, c.first, c.last, c.upTo);
        if (!owed) continue;
        let got = 0;
        let x = this.nextOf[c.upTo - 1];
        for (; x && got < owed && steps > 0; x = this.nextOf[x - 1], steps--) {
          if (Math.sign(this.flowOf[x - 1]) === side) continue;
          if (!out.add(x)) break;
          got++;
        }
        // Owed still: an answer may come, unless the other side has been quiet for a while
        if (got < owed && (x || !this.over(flow, -side))) openFlows.add(id);
      }
    }
    // Those shorter than an even share of the budget left first, the shortest first: a long one may be a new message
    const later = walks.filter((w) => !w.cut);
    const share = Math.max(1, (budget.frames - out.size) / later.length);
    const length = new Map<Walk, number>();
    for (const w of later) {
      const probe = { ...w };
      const n = this.walk(probe, 2 * MAX_PIPELINED, out, share);
      length.set(w, probe.cut ? Infinity : n);
    }
    later.sort((a, b) => length.get(a)! - length.get(b)!);
    for (const w of later) {
      this.walk(w, 2 * MAX_PIPELINED, out);
      if (!w.cut && this.mayChange(w)) openFlows.add(w.id);
    }
    return { frames: out.sorted(), open: openFlows.size > 0 };
  }

  /** The flow `frame` belongs to, 0 for none. */
  idOf(frame: number): number {
    return frame >= 1 && frame <= this.count ? Math.abs(this.flowOf[frame - 1]) : 0;
  }

  /** The first frame of the flow `frame` belongs to, or null when unknown. */
  firstOf(frame: number): number | null {
    if (frame < 1 || frame > this.count) return null;
    return this.byId.get(Math.abs(this.flowOf[frame - 1]))?.heads[0] ?? null;
  }

  /**
   * Walks `w` on while its turns since its side's last data in the chunk are
   * at most `turns` (0: that side's run; 2: past a short run of the other
   * side's, its next one) and the other side's runs are short, taking its
   * packets up to its side's last one with data; with `probe`, only counting
   * them, within that many frames. Returns how many.
   */
  private walk(w: Walk, turns: number, out: Taken, probe = 0): number {
    const run: number[] = [];
    let sent = 0;
    let bytes = 0;
    const frames = Math.min(out.budget.frames - out.size, probe || Infinity);
    const room = out.budget.bytes - out.bytes;
    for (; w.x && Math.abs(this.flowOf[w.x - 1]) === w.id; w.x = this.nextOf[w.x - 1]) {
      const x = w.x;
      if (run.length >= frames || bytes + out.budget.size(x) > room) {
        // Cut short, unless the walk ends here anyway
        w.cut = this.step({ ...w }, x, turns);
        break;
      }
      if (!this.step(w, x, turns)) break;
      run.push(x);
      bytes += out.budget.size(x);
      if (this.data[x - 1] && Math.sign(this.flowOf[x - 1]) === w.side) sent = run.length;
    }
    if (!probe) out.addAll(run.slice(0, sent));
    return sent;
  }

  /** Whether what `w` took may still change: the budget cut it short, or it reached the newest packet while its side may still send. */
  private mayChange(w: Walk): boolean {
    return w.cut || (!w.x && !this.over(this.byId.get(w.id), w.side));
  }

  /** Whether no more data comes from the side `side` of `flow`: its FIN, a RST, or it has been quiet for IDLE seconds. */
  private over(flow: Flow | undefined, side: number): boolean {
    if (!flow) return false;
    const i = side > 0 ? 0 : 1;
    return flow.ended[i] || this.time - flow.times[i] > IDLE;
  }

  /**
   * Moves `w` past `x`, unless that takes it past `turns` turns, into a long
   * run of the other side's or to a run of its side's that starts a new
   * message: false then.
   */
  private step(w: Turns, x: number, turns: number): boolean {
    const turn = this.turnOf[x - 1];
    const past = w.turns + (turn !== w.turn ? 1 : 0);
    // The other side's runs are the odd turns
    const interleaved = past % 2 ? (past === w.turns ? w.interleaved : 0) + (this.data[x - 1] ? 1 : 0) : 0;
    if (past > turns || interleaved > MAX_INTERLEAVED) return false;
    // The message under way ended before the other side's run
    if (past > w.turns && past % 2 === 0 && this.data[x - 1] === STARTS) return false;
    w.turn = turn;
    w.turns = past;
    w.interleaved = interleaved;
    return true;
  }

  /**
   * Answers the side `side` of a non-TCP flow is owed for its packets in the
   * chunk (first..last there, last up to hi `upTo`): what it sent up to the
   * chunk's end beyond what the other side sent up to hi, as an answer
   * follows each packet. None when its packets before the chunk weren't all
   * answered by hi either (a host that stopped answering, more sent one way
   * than the other), or when past its first packets the other side sent less
   * than one for every four of its up to hi (a flow mostly one way: a
   * stream, a download over QUIC or a tunnel).
   */
  private owed(side: number, first: number, last: number, upTo: number): number {
    const asked = this.sentBy(upTo, side);
    const answers = this.sentBy(upTo, -side);
    if (asked + answers > HEAD_FRAMES && 4 * answers < asked) return 0;
    const inChunk = this.sentBy(last, side) - this.sentBy(first, side) + (Math.sign(this.flowOf[first - 1]) === side ? 1 : 0);
    const owed = this.sentBy(last, side) - answers;
    return owed > inChunk ? 0 : Math.max(0, Math.min(owed, MAX_ANSWERS));
  }

  /** Packets of the flow of `frame` from the side `side` (1: the lower address) up to it. */
  private sentBy(frame: number, side: number): number {
    const forward = this.forwardOf[frame - 1] + (this.flowOf[frame - 1] > 0 ? 1 : 0);
    return side > 0 ? forward : this.ordOf[frame - 1] + 1 - forward;
  }

  /**
   * Where the messages under way at `p` start, `turns` exchanges back: right
   * after the current side's run of data before the other side's last run
   * (turns 1), or before its turns-th last; the flow's start when there is
   * none. 0 when unknown.
   */
  private messageStart(p: number, turns: number): number {
    let at = p;
    for (let k = 0; k < 2 * turns && at; k++) at = this.turnOf[at - 1];
    return (at && this.nextOf[at - 1]) || this.firstOf(p) || 0;
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
  /** Bytes taken. */
  bytes = 0;

  constructor(readonly budget: Budget) {}

  /** Frames taken. */
  get size(): number {
    return this.frames.size;
  }

  has(frame: number): boolean {
    return this.frames.has(frame);
  }

  /** Takes `frame` if it fits; true when it is taken. */
  add(frame: number): boolean {
    if (this.frames.has(frame)) return true;
    const size = this.budget.size(frame);
    if (this.frames.size >= this.budget.frames || this.bytes + size > this.budget.bytes) return false;
    this.frames.add(frame);
    this.bytes += size;
    return true;
  }

  /** Takes all of `frames` if they fit; true when all are taken. */
  addAll(frames: number[]): boolean {
    const fresh = frames.filter((f) => !this.frames.has(f));
    const size = fresh.reduce((n, f) => n + this.budget.size(f), 0);
    if (this.frames.size + fresh.length > this.budget.frames || this.bytes + size > this.budget.bytes) return false;
    for (const f of fresh) this.add(f);
    return true;
  }

  sorted(): Int32Array {
    return Int32Array.from(this.frames).sort();
  }
}

/** Whether TCP payload b[at..end) starts a message: an HTTP/1 status or request line, a TLS record. */
function startsMessage(b: Buffer, at: number, end: number): boolean {
  // A TLS record: change cipher spec, alert, handshake or application data, version 3.x
  if (end - at >= 5 && b[at] >= 20 && b[at] <= 23 && b[at + 1] === 3 && b[at + 2] <= 4) return true;
  return HTTP_START.test(b.toString("latin1", at, Math.min(end, at + 16)));
}

function grown(a: Int32Array<ArrayBuffer>): Int32Array<ArrayBuffer> {
  const b = new Int32Array(a.length * 2);
  b.set(a);
  return b;
}
