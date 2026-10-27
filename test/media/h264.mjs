// A tiny lossless H.264 encoder for test clips: Constrained Baseline, CAVLC, every
// macroblock I_PCM (raw samples). IDR pictures code all macroblocks; P pictures only the
// ones that changed and skip the rest. Deterministic, no dependencies.

class Bits {
  bytes = [];
  cur = 0;
  n = 0;
  bit(b) {
    this.cur = (this.cur << 1) | b;
    if (++this.n === 8) {
      this.bytes.push(this.cur);
      this.cur = 0;
      this.n = 0;
    }
  }
  u(bits, v) {
    for (let i = bits - 1; i >= 0; i--) this.bit((v >>> i) & 1);
  }
  ue(v) {
    const len = 32 - Math.clz32(v + 1);
    this.u(len - 1, 0);
    this.u(len, v + 1);
  }
  se(v) {
    this.ue(v <= 0 ? -2 * v : 2 * v - 1);
  }
  align() {
    while (this.n) this.bit(0);
  }
  trailing() {
    this.bit(1);
    this.align();
  }
}

/** A NAL unit with emulation prevention, without a start code. */
function nal(refIdc, type, rbsp) {
  const out = [(refIdc << 5) | type];
  let zeros = 0;
  for (const b of rbsp) {
    if (zeros >= 2 && b <= 3) {
      out.push(3);
      zeros = 0;
    }
    out.push(b);
    zeros = b === 0 ? zeros + 1 : 0;
  }
  return Uint8Array.from(out);
}

const LOG2_MAX_FRAME_NUM = 4;

function sps(width, height) {
  const b = new Bits();
  b.u(8, 66); // Baseline
  b.u(8, 0xc0); // constraint_set0 and 1: Constrained Baseline
  b.u(8, 30); // level 3.0
  b.ue(0); // seq_parameter_set_id
  b.ue(LOG2_MAX_FRAME_NUM - 4);
  b.ue(2); // pic_order_cnt_type: output order is decoding order
  b.ue(1); // max_num_ref_frames
  b.u(1, 0);
  b.ue(width / 16 - 1);
  b.ue(height / 16 - 1);
  b.u(1, 1); // frame_mbs_only_flag
  b.u(1, 1); // direct_8x8_inference_flag
  b.u(1, 0); // frame_cropping_flag
  b.u(1, 0); // vui_parameters_present_flag
  b.trailing();
  return nal(3, 7, b.bytes);
}

function pps() {
  const b = new Bits();
  b.ue(0);
  b.ue(0);
  b.u(1, 0); // CAVLC
  b.u(1, 0);
  b.ue(0); // one slice group
  b.ue(0);
  b.ue(0);
  b.u(1, 0);
  b.u(2, 0);
  b.se(0); // pic_init_qp_minus26
  b.se(0);
  b.se(0);
  b.u(1, 1); // deblocking_filter_control_present_flag
  b.u(1, 0);
  b.u(1, 0);
  b.trailing();
  return nal(3, 8, b.bytes);
}

/** A picture's macroblock `i` as 384 raw bytes: 16x16 Y, then 8x8 Cb and Cr. */
function macroblock(pic, i) {
  const mbw = pic.width / 16;
  const x0 = (i % mbw) * 16;
  const y0 = Math.floor(i / mbw) * 16;
  const out = new Uint8Array(384);
  for (let y = 0; y < 16; y++) out.set(pic.y.subarray((y0 + y) * pic.width + x0, (y0 + y) * pic.width + x0 + 16), y * 16);
  const cw = pic.width / 2;
  for (let y = 0; y < 8; y++) {
    const at = (y0 / 2 + y) * cw + x0 / 2;
    out.set(pic.u.subarray(at, at + 8), 256 + y * 8);
    out.set(pic.v.subarray(at, at + 8), 320 + y * 8);
  }
  return out;
}

function pcm(b, mb) {
  b.align();
  for (const s of mb) b.u(8, s);
}

/** A slice of the whole picture: IDR when `prev` is null, else P with unchanged macroblocks skipped. */
function slice(pic, prev, frameNum, idrId) {
  const b = new Bits();
  const idr = prev === null;
  b.ue(0); // first_mb_in_slice
  b.ue(idr ? 7 : 5); // I or P, all slices of the picture alike
  b.ue(0);
  b.u(LOG2_MAX_FRAME_NUM, frameNum);
  if (idr) b.ue(idrId);
  if (!idr) {
    b.u(1, 0); // num_ref_idx_active_override_flag
    b.u(1, 0); // ref_pic_list_modification_flag_l0
  }
  if (idr) b.u(2, 0); // no_output_of_prior_pics_flag, long_term_reference_flag
  else b.u(1, 0); // adaptive_ref_pic_marking_mode_flag
  b.se(0); // slice_qp_delta
  b.ue(1); // deblocking off
  const count = (pic.width / 16) * (pic.height / 16);
  let skipped = 0;
  for (let i = 0; i < count; i++) {
    const mb = macroblock(pic, i);
    if (!idr) {
      const old = macroblock(prev, i);
      if (mb.every((v, k) => v === old[k])) {
        skipped++;
        continue;
      }
      b.ue(skipped);
      skipped = 0;
    }
    b.ue(idr ? 25 : 30); // I_PCM
    pcm(b, mb);
  }
  if (skipped) b.ue(skipped);
  b.trailing();
  return idr ? nal(3, 5, b.bytes) : nal(2, 1, b.bytes);
}

/**
 * Encodes pictures ({width, height, y, u, v}: 4:2:0, sizes multiples of 16) into access units:
 * arrays of NAL units, an IDR (with SPS and PPS) every `gop` pictures.
 */
export function encode(pictures, gop = 30) {
  const out = [];
  let prev = null;
  let frameNum = 0;
  let idrs = 0;
  pictures.forEach((pic, i) => {
    if (i % gop === 0) {
      out.push([sps(pic.width, pic.height), pps(), slice(pic, null, 0, idrs++ % 2)]);
      frameNum = 0;
    } else {
      frameNum = (frameNum + 1) % (1 << LOG2_MAX_FRAME_NUM);
      out.push([slice(pic, prev, frameNum, 0)]);
    }
    prev = pic;
  });
  return out;
}

/** Annex B byte stream of access units. */
export function annexB(units) {
  const parts = [];
  for (const au of units) for (const n of au) parts.push(Uint8Array.of(0, 0, 0, 1), n);
  return Buffer.concat(parts);
}

const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, Math.round(v)));

/**
 * `count` pictures of a ball bouncing over a gradient, a progress bar at the bottom;
 * `hue` (degrees) tints the ball.
 */
export function bouncingBall(width, height, count, hue = 20) {
  const pics = [];
  const r = Math.min(width, height) / 6;
  const rad = (hue * Math.PI) / 180;
  const ball = { y: 150, u: 128 + 90 * Math.cos(rad), v: 128 + 90 * Math.sin(rad) };
  for (let f = 0; f < count; f++) {
    const y = new Uint8Array(width * height);
    const u = new Uint8Array((width * height) / 4);
    const v = new Uint8Array((width * height) / 4);
    const t = f / count;
    const cx = r + (width - 2 * r) * (t < 0.5 ? 2 * t : 2 - 2 * t);
    const cy = r + (height - 2 * r - 12) * Math.abs(Math.sin(t * Math.PI * 3));
    const bar = Math.round(((f + 1) / count) * width);
    for (let py = 0; py < height; py++) {
      for (let px = 0; px < width; px++) {
        const d = Math.hypot(px - cx, py - cy);
        let val = 40 + (px / width) * 60 + (py / height) * 30;
        if (d < r) val = ball.y - (d / r) * 40;
        if (py >= height - 6 && px < bar) val = 200;
        y[py * width + px] = clamp(val, 16, 235);
      }
    }
    for (let py = 0; py < height / 2; py++) {
      for (let px = 0; px < width / 2; px++) {
        const d = Math.hypot(px * 2 + 1 - cx, py * 2 + 1 - cy);
        const inBall = d < r;
        u[py * (width / 2) + px] = clamp(inBall ? ball.u : 128 + (px / width) * 30, 16, 240);
        v[py * (width / 2) + px] = clamp(inBall ? ball.v : 118 - (py / height) * 20, 16, 240);
      }
    }
    pics.push({ width, height, y, u, v });
  }
  return pics;
}
