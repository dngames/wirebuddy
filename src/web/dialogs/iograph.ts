/** Statistics > I/O Graphs: up to four packet/byte/bit rate lines over time. */

import type { FilterCheck, FrameDetail, IoGraphResult, IoGraphSpec } from "../../shared/api.ts";
import { errorText, get } from "../api.ts";
import * as act from "../actions.ts";
import { app, bus, captureActive } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { icon } from "../icons.ts";
import { toast } from "../toast.ts";
import { clamp, debounce, fmtInt, h } from "../util.ts";

type Metric = IoGraphSpec["metric"];

const INTERVALS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000];
const COLORS = ["#2e6fd8", "#d9302c", "#2e9d3a", "#e08a00"];
const METRIC_LABEL: Record<Metric, string> = { packets: "Packets", bytes: "Bytes", bits: "Bits" };
const SVGNS = "http://www.w3.org/2000/svg";

interface Graph {
  enabled: boolean;
  metric: Metric;
  filter: string;
  color: string;
  status: "ok" | "error" | "checking";
  error: string;
}

function svg<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string | number>, text?: string): SVGElementTagNameMap[K] {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  if (text !== undefined) el.textContent = text;
  return el;
}

/** Smallest interval that keeps the capture within 500 buckets. */
function autoInterval(durationSec: number): number {
  const ms = Math.max(0, durationSec) * 1000;
  for (const iv of INTERVALS) if (ms / iv <= 500) return iv;
  return INTERVALS[INTERVALS.length - 1];
}

export function fmtInterval(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${ms / 1000} s`;
}

function fmtCompact(v: number): string {
  const a = Math.abs(v);
  if (a >= 1e9) return `${+(v / 1e9).toFixed(2)}G`;
  if (a >= 1e6) return `${+(v / 1e6).toFixed(2)}M`;
  if (a >= 1e4) return `${+(v / 1e3).toFixed(1)}k`;
  return Number.isInteger(v) ? String(v) : String(+v.toFixed(2));
}

/** 1-2-5 step so that about `count` ticks cover [0, max]. */
function niceTicks(max: number, count: number): { top: number; step: number; ticks: number[] } {
  const m = max > 0 ? max : 1;
  const raw = m / Math.max(1, count);
  const p = 10 ** Math.floor(Math.log10(raw));
  const f = raw / p;
  const step = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
  const top = Math.ceil(m / step - 1e-9) * step;
  const ticks: number[] = [];
  for (let k = 0; k * step <= top + step * 1e-9; k++) ticks.push(k * step);
  return { top, step, ticks };
}

function decimalsFor(step: number): number {
  return step >= 1 ? 0 : Math.min(6, Math.ceil(-Math.log10(step) - 1e-9));
}

/** Seconds since the first frame, from the frame's `frame.time_relative` field; null if unknown. */
async function frameTime(num: number): Promise<number | null> {
  const fd = await get<FrameDetail>("api/frame", { num });
  for (const top of fd.tree ?? []) {
    for (const n of top.n ?? []) {
      if (n.fn !== "frame.time_relative") continue;
      const m = /==\s*(-?[\d.]+)/.exec(n.f ?? "") ?? /(-?\d+\.\d+)/.exec(n.l);
      const v = m ? Number(m[1]) : NaN;
      return Number.isFinite(v) ? v : null;
    }
  }
  return null;
}

let current: Dialog | null = null;

export function openIoGraphDialog(): void {
  if (current?.isOpen) {
    current.raise();
    return;
  }
  const s = app.state;
  if (!s?.file) return;
  const d = new Dialog("I/O Graphs", { width: 940, height: 600, cls: "dlg-stats dlg-io", modal: false });
  current = d;

  const graphs: Graph[] = COLORS.map((color, k) => ({
    enabled: k === 0 || (k === 1 && !!s.filter),
    metric: "packets",
    filter: k === 1 ? s.filter : "",
    color,
    status: "ok",
    error: "",
  }));

  const chartBox = h("div", { class: "io-chart" });
  const chartSvg = svg("svg", { class: "io-svg", role: "img", "aria-label": "I/O graph" });
  const tip = h("div", { class: "io-tip", hidden: true });
  const msg = h("div", { class: "stat-msg io-msg" }, "Loading…");
  chartBox.append(chartSvg, tip, msg);

  const intervalSel = h("select", { class: "io-interval", attrs: { "aria-label": "Interval" } });
  const autoOpt = h("option", { value: "auto" }, "Auto");
  intervalSel.append(autoOpt, ...INTERVALS.map((iv) => h("option", { value: String(iv) }, fmtInterval(iv))));
  const ivNote = h("span", { class: "io-ivnote" });
  const refreshBtn = h("button", { class: "btn", title: "Recompute the graphs" }, icon("refresh"), h("span", null, "Refresh"));

  let res: IoGraphResult | null = null;
  let resGraphs: Graph[] = [];
  let inflight = false;
  let again = false;
  let loadSeq = 0;
  // Plot geometry of the last draw, for hover and click.
  let geo: { ml: number; mt: number; pw: number; ph: number; n: number; ivS: number; tMax: number } | null = null;
  let crosshair: SVGLineElement | null = null;

  const showMsg = (text: string | null, error = false): void => {
    msg.hidden = !text;
    msg.textContent = text ?? "";
    msg.classList.toggle("error", error);
  };

  const requestedInterval = (): number => (intervalSel.value === "auto" ? autoInterval(app.state?.duration ?? 0) : Number(intervalSel.value));

  const updateAutoLabel = (): void => {
    autoOpt.textContent = `Auto (${fmtInterval(autoInterval(app.state?.duration ?? 0))})`;
  };

  const graphLabel = (g: Graph): string => {
    const k = graphs.indexOf(g) + 1;
    const f = g.filter.trim();
    return `Graph ${k}: ${f ? (f.length > 48 ? `${f.slice(0, 47)}…` : f) : "all packets"}`;
  };

  const draw = (): void => {
    chartSvg.replaceChildren();
    tip.hidden = true;
    crosshair = null;
    geo = null;
    const W = chartBox.clientWidth;
    const H = chartBox.clientHeight;
    if (!res || !res.series.length || W < 120 || H < 80) return;
    chartSvg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    chartSvg.setAttribute("width", String(W));
    chartSvg.setAttribute("height", String(H));
    const series = res.series.map((sr, k) => ({ ...sr, graph: resGraphs[k] }));
    const leftMetric = series[0].metric;
    const left = series.filter((x) => x.metric === leftMetric);
    const right = series.filter((x) => x.metric !== leftMetric);
    const ml = 64;
    const mr = right.length ? 64 : 18;
    const mt = 14;
    const mb = 38;
    const pw = Math.max(10, W - ml - mr);
    const ph = Math.max(10, H - mt - mb);
    const n = Math.max(1, ...series.map((x) => x.values.length));
    const ivS = res.interval / 1000;
    const tMax = n * ivS;
    geo = { ml, mt, pw, ph, n, ivS, tMax };
    const xs = (t: number): number => ml + (t / tMax) * pw;
    const maxOf = (list: typeof series): number => Math.max(0, ...list.flatMap((x) => x.values));
    const yCount = Math.max(2, Math.floor(ph / 45));
    const axL = niceTicks(maxOf(left), yCount);
    const axR = right.length ? niceTicks(maxOf(right), yCount) : null;
    const yL = (v: number): number => mt + ph - (v / axL.top) * ph;
    const yR = (v: number): number => mt + ph - (v / (axR?.top || 1)) * ph;

    const grid = svg("g", { class: "io-gridg" });
    for (const v of axL.ticks) {
      grid.append(svg("line", { class: "io-grid", x1: ml, x2: ml + pw, y1: yL(v), y2: yL(v) }));
      grid.append(svg("text", { class: "io-tick", x: ml - 6, y: yL(v) + 4, "text-anchor": "end" }, fmtCompact(v)));
    }
    if (axR) {
      for (const v of axR.ticks) grid.append(svg("text", { class: "io-tick", x: ml + pw + 6, y: yR(v) + 4, "text-anchor": "start" }, fmtCompact(v)));
    }
    const xt = niceTicks(tMax, Math.max(2, Math.floor(pw / 90)));
    const dec = decimalsFor(xt.step);
    for (const t of xt.ticks) {
      if (t > tMax + 1e-9) continue;
      grid.append(svg("line", { class: "io-axis", x1: xs(t), x2: xs(t), y1: mt + ph, y2: mt + ph + 4 }));
      grid.append(svg("text", { class: "io-tick", x: xs(t), y: mt + ph + 17, "text-anchor": "middle" }, t.toFixed(dec)));
    }
    grid.append(svg("line", { class: "io-axis", x1: ml, x2: ml, y1: mt, y2: mt + ph }));
    grid.append(svg("line", { class: "io-axis", x1: ml, x2: ml + pw, y1: mt + ph, y2: mt + ph }));
    if (axR) grid.append(svg("line", { class: "io-axis", x1: ml + pw, x2: ml + pw, y1: mt, y2: mt + ph }));
    grid.append(svg("text", { class: "io-label", x: ml + pw / 2, y: H - 4, "text-anchor": "middle" }, "Time (s)"));
    const ivText = fmtInterval(res.interval);
    grid.append(svg("text", { class: "io-label", x: 14, y: mt + ph / 2, "text-anchor": "middle", transform: `rotate(-90 14 ${mt + ph / 2})` }, `${METRIC_LABEL[leftMetric]}/${ivText}`));
    if (axR) {
      const rm = [...new Set(right.map((x) => METRIC_LABEL[x.metric]))].join(", ");
      grid.append(svg("text", { class: "io-label", x: W - 10, y: mt + ph / 2, "text-anchor": "middle", transform: `rotate(90 ${W - 10} ${mt + ph / 2})` }, `${rm}/${ivText}`));
    }
    chartSvg.append(grid);

    for (const sr of series) {
      const y = sr.metric === leftMetric ? yL : yR;
      if (sr.values.length === 1) {
        chartSvg.append(svg("circle", { cx: xs(0), cy: y(sr.values[0]), r: 3, fill: sr.graph?.color ?? "#888" }));
        continue;
      }
      let dPath = "";
      sr.values.forEach((v, i) => {
        dPath += `${i ? "L" : "M"}${xs(i * ivS).toFixed(1)},${y(v).toFixed(1)}`;
      });
      chartSvg.append(svg("path", { class: "io-line", d: dPath, stroke: sr.graph?.color ?? "#888" }));
    }

    const legend = svg("g", { class: "io-legend" });
    series.forEach((sr, k) => {
      const ly = mt + 6 + k * 16;
      legend.append(svg("rect", { x: ml + 10, y: ly, width: 14, height: 3, fill: sr.graph?.color ?? "#888" }));
      const side = right.length ? (sr.metric === leftMetric ? " (left)" : " (right)") : "";
      legend.append(svg("text", { class: "io-legend-text", x: ml + 30, y: ly + 5 }, `${sr.graph ? graphLabel(sr.graph) : `Graph ${k + 1}`} · ${METRIC_LABEL[sr.metric]}${side}`));
    });
    chartSvg.append(legend);
    crosshair = svg("line", { class: "io-cross", x1: 0, x2: 0, y1: mt, y2: mt + ph, visibility: "hidden" });
    chartSvg.append(crosshair);
  };

  const refresh = async (): Promise<void> => {
    const enabled = graphs.filter((g) => g.enabled && g.status === "ok");
    if (!enabled.length) {
      // Drop whatever is still in flight.
      loadSeq++;
      again = false;
      res = null;
      draw();
      showMsg(graphs.some((g) => g.enabled) ? "Fix the display filters of the enabled graphs" : "Enable at least one graph");
      return;
    }
    if (inflight) {
      again = true;
      return;
    }
    inflight = true;
    const seq = ++loadSeq;
    const reqIv = requestedInterval();
    if (!res) showMsg("Loading…");
    try {
      const specs: IoGraphSpec[] = enabled.map((g) => ({ metric: g.metric, filter: g.filter.trim() }));
      const r = await get<IoGraphResult>("api/stats/iograph", { interval: reqIv, graphs: JSON.stringify(specs) });
      if (seq !== loadSeq || !d.isOpen) return;
      res = r;
      resGraphs = enabled;
      ivNote.textContent = r.interval !== reqIv ? `Using ${fmtInterval(r.interval)} (raised by the server)` : `${fmtInt(Math.max(0, ...r.series.map((x) => x.values.length)))} intervals`;
      showMsg(r.series.every((x) => !x.values.length) ? "No packets" : null);
      draw();
    } catch (e) {
      if (seq === loadSeq) showMsg(`Failed: ${errorText(e)}`, true);
    } finally {
      inflight = false;
      if (again && d.isOpen) {
        again = false;
        void refresh();
      }
    }
  };
  const refreshSoon = debounce(() => void refresh(), 300);

  // ------------------------------------------------------------ graph table
  const tbody = h("tbody");
  graphs.forEach((g, k) => {
    const en = h("input", { type: "checkbox", checked: g.enabled, attrs: { "aria-label": `Enable graph ${k + 1}` } });
    const color = h("input", { type: "color", class: "io-color", value: g.color, attrs: { "aria-label": `Color of graph ${k + 1}` } });
    const filter = h("input", { type: "text", class: "io-filter", value: g.filter, spellcheck: false, placeholder: "All packets (display filter)", attrs: { "aria-label": `Display filter of graph ${k + 1}` } });
    const metric = h(
      "select",
      { attrs: { "aria-label": `Metric of graph ${k + 1}` } },
      h("option", { value: "packets" }, "Packets"),
      h("option", { value: "bytes" }, "Bytes"),
      h("option", { value: "bits" }, "Bits"),
    );
    metric.value = g.metric;
    const paint = (): void => {
      filter.classList.toggle("valid", g.status === "ok" && !!g.filter.trim());
      filter.classList.toggle("invalid", g.status === "error");
      filter.title = g.status === "error" ? g.error : "";
    };
    let checkSeq = 0;
    const check = debounce(async () => {
      const seq = ++checkSeq;
      const f = g.filter.trim();
      if (!f) {
        g.status = "ok";
        paint();
        refreshSoon();
        return;
      }
      try {
        const r = await get<FilterCheck>("api/filter/check", { filter: f });
        if (seq !== checkSeq) return;
        g.status = r.ok ? "ok" : "error";
        g.error = r.error ?? "";
      } catch (e) {
        if (seq !== checkSeq) return;
        g.status = "error";
        g.error = errorText(e);
      }
      paint();
      if (g.enabled) refreshSoon();
    }, 300);
    en.addEventListener("change", () => {
      g.enabled = en.checked;
      refreshSoon();
    });
    color.addEventListener("input", () => {
      g.color = color.value;
      draw();
    });
    metric.addEventListener("change", () => {
      g.metric = metric.value as Metric;
      refreshSoon();
    });
    filter.addEventListener("input", () => {
      g.filter = filter.value;
      g.status = "checking";
      check();
    });
    filter.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        check.flush();
      }
    });
    if (g.filter) {
      g.status = "checking";
      check();
    }
    paint();
    tbody.append(h("tr", null, h("td", null, en), h("td", null, color), h("td", { class: "io-name" }, `Graph ${k + 1}`), h("td", { class: "io-fcell" }, filter), h("td", null, metric)));
  });
  const table = h(
    "table",
    { class: "io-table" },
    h("thead", null, h("tr", null, h("th", null, "On"), h("th", null, "Color"), h("th", { class: "left" }, "Name"), h("th", { class: "left" }, "Display filter"), h("th", { class: "left" }, "Y axis"))),
    tbody,
  );

  // ------------------------------------------------------- hover and click
  const bucketAt = (clientX: number): { i: number; t: number } | null => {
    if (!geo) return null;
    const r = chartSvg.getBoundingClientRect();
    const x = clientX - r.left;
    if (x < geo.ml || x > geo.ml + geo.pw) return null;
    const t = ((x - geo.ml) / geo.pw) * geo.tMax;
    return { i: clamp(Math.floor(t / geo.ivS), 0, geo.n - 1), t };
  };

  chartSvg.addEventListener("mousemove", (e: MouseEvent) => {
    const b = bucketAt(e.clientX);
    if (!b || !geo || !res || !crosshair) {
      tip.hidden = true;
      crosshair?.setAttribute("visibility", "hidden");
      return;
    }
    const x = geo.ml + ((b.i * geo.ivS) / geo.tMax) * geo.pw;
    crosshair.setAttribute("x1", String(x));
    crosshair.setAttribute("x2", String(x));
    crosshair.setAttribute("visibility", "visible");
    const dec = decimalsFor(geo.ivS);
    tip.replaceChildren(h("div", { class: "io-tip-t" }, `${(b.i * geo.ivS).toFixed(dec)} s – ${((b.i + 1) * geo.ivS).toFixed(dec)} s`));
    res.series.forEach((sr, k) => {
      const g = resGraphs[k];
      tip.append(
        h(
          "div",
          { class: "io-tip-row" },
          h("span", { class: "io-swatch", style: `background:${g?.color ?? "#888"}` }),
          `${g ? `Graph ${graphs.indexOf(g) + 1}` : `Graph ${k + 1}`}: `,
          h("b", null, fmtInt(sr.values[b.i] ?? 0)),
          ` ${METRIC_LABEL[sr.metric].toLowerCase()}`,
        ),
      );
    });
    tip.append(h("div", { class: "io-tip-hint" }, "Click to go to the packet at this time"));
    tip.hidden = false;
    const br = chartBox.getBoundingClientRect();
    const px = e.clientX - br.left;
    const py = e.clientY - br.top;
    const left = px + 14 + tip.offsetWidth > br.width ? px - 14 - tip.offsetWidth : px + 14;
    tip.style.left = `${Math.max(0, left)}px`;
    tip.style.top = `${clamp(py - 10, 0, Math.max(0, br.height - tip.offsetHeight))}px`;
  });
  chartSvg.addEventListener("mouseleave", () => {
    tip.hidden = true;
    crosshair?.setAttribute("visibility", "hidden");
  });
  chartSvg.addEventListener("click", async (e: MouseEvent) => {
    const b = bucketAt(e.clientX);
    if (!b || !geo) return;
    // The bucket under the crosshair, not the exact cursor time.
    const t0 = b.i * geo.ivS;
    const t1 = (b.i + 1) * geo.ivS;
    const dec = Math.max(3, decimalsFor(geo.ivS));
    const span = `${t0.toFixed(dec)} s – ${t1.toFixed(dec)} s`;
    try {
      const r = await get<{ frame: number | null }>("api/frame-at", { t: t0.toFixed(9) });
      if (r.frame === null || r.frame === undefined) {
        toast("info", `No packet in this interval (${span})`);
        return;
      }
      const ft = await frameTime(r.frame);
      if (ft !== null && (ft < t0 - 1e-9 || ft >= t1 - 1e-9)) {
        toast("info", `No packet in this interval (${span})`);
        return;
      }
      act.jumpToFrame(r.frame);
    } catch (err) {
      toast("error", `Finding the packet at ${t0.toFixed(dec)} s failed: ${errorText(err)}`);
    }
  });

  new ResizeObserver(() => draw()).observe(chartBox);
  intervalSel.addEventListener("change", () => void refresh());
  refreshBtn.addEventListener("click", () => void refresh());

  updateAutoLabel();
  // Live capture: follow the growing file.
  const timer = window.setInterval(() => {
    if (captureActive()) {
      updateAutoLabel();
      void refresh();
    }
  }, 2000);
  const offState = bus.on("state", (st, prev) => {
    if (!prev) return;
    if (st.file !== prev.file) {
      updateAutoLabel();
      void refresh();
    } else if (!captureActive(st) && (st.totalFrames !== prev.totalFrames || st.duration !== prev.duration)) {
      // Final reload after a capture stops, or a re-dissection: the live timer no longer runs.
      updateAutoLabel();
      refreshSoon();
    }
  });

  d.body.append(
    chartBox,
    h("div", { class: "io-controls" }, h("label", { class: "fl-lbl" }, "Interval", intervalSel), ivNote, h("span", { class: "fl-spacer" }), refreshBtn),
    h("div", { class: "io-table-wrap" }, table),
  );
  d.footerLeft.textContent = "Time is relative to the first packet";
  d.button("Close", () => d.close(), { primary: true });
  d.onClose = () => {
    refreshSoon.cancel();
    window.clearInterval(timer);
    offState();
    current = null;
  };
  d.show(intervalSel);
  void refresh();
}
