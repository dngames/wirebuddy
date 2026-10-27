/** Status bar: expert LED, file, field info, packet counts, marks, capture, connection. */

import type { ExpertItem, ExpertSeverity, ViewState } from "../shared/api.ts";
import { countRanges } from "../shared/ranges.ts";
import { APP_NAME, get } from "./api.ts";
import { app, bus } from "./app.ts";
import { captureStatusText } from "./capture.ts";
import { maxItemSeverity, openExpertDialog } from "./dialogs/expert.ts";
import { openTlsDialog } from "./dialogs/tls.ts";
import { maxSeverity, sevClass } from "./frame.ts";
import { icon } from "./icons.ts";
import { baseName, fmtInt, fmtPct, fmtSize, h, setText, setTitle } from "./util.ts";
import { reconnectNow } from "./ws.ts";

export function createStatusBar(): HTMLElement {
  const led = h("button", { class: "sb-led", attrs: { "aria-label": "Expert information" }, onclick: () => openExpertDialog() });
  const tlsSeg = h("button", { class: "sb-seg sb-tls", hidden: true, onclick: () => openTlsDialog() }, icon("lock"), "TLS keys");
  const fileSeg = h("span", { class: "sb-seg sb-file" });
  const errSeg = h("span", { class: "sb-seg sb-err", hidden: true }, "Open failed");
  const fieldSeg = h("span", { class: "sb-seg sb-field" });
  const pktSeg = h("span", { class: "sb-seg sb-pkts" });
  const markSeg = h("span", { class: "sb-seg sb-marks" });
  const capSeg = h("span", { class: "sb-seg sb-cap" });
  const connSeg = h("button", { class: "sb-seg sb-conn", onclick: () => reconnectNow() });
  const agentSeg = h(
    "span",
    {
      class: "sb-seg sb-agent",
      hidden: true,
      title: "Problems Claude gets with its next WireBuddy call, or at once while it watches the viewer. If nothing happens, ask Claude in the chat.",
    },
  );
  let fieldText = "";

  // Capture-wide expert severity: only for finished captures of moderate size.
  let capSev: ExpertSeverity | null = null;
  let capKnown = false;
  let capKey = "";
  let capFile = "";
  let capSeq = 0;
  const syncCaptureExpert = (s: ViewState): void => {
    const live = s.capture.status !== "idle" && s.capture.status !== "error";
    if (!s.file || s.loading || live || s.totalFrames <= 0 || s.totalFrames > 200_000) {
      capKnown = false;
      capKey = "";
      capSeq++;
      return;
    }
    // Only what changes dissection; filter and column changes don't.
    const key = `${s.instance}|${s.file}|${s.fileSize}|${s.totalFrames}|${s.tlsKeylog ?? ""}`;
    if (key === capKey) return;
    if (s.file !== capFile) capKnown = false;
    capKey = key;
    capFile = s.file;
    const seq = ++capSeq;
    get<ExpertItem[]>("api/stats/expert")
      .then((items) => {
        if (seq !== capSeq) return;
        capSev = maxItemSeverity(Array.isArray(items) ? items : []);
        capKnown = true;
        update();
      })
      .catch(() => {
        if (seq !== capSeq) return;
        capKnown = false;
        update();
      });
  };

  const update = (): void => {
    const s = app.state;
    const sev = capKnown ? capSev : maxSeverity(app.frame);
    led.className = `sb-led ${sev ? sevClass(sev) : "none"}`;
    const scope = capKnown ? "this capture" : "this packet";
    setTitle(led, `${sev ? `Highest expert severity in ${scope}: ${sev}` : `No expert information for ${scope}`}. Click for Expert Information.`);
    const tls = s?.tlsKeylog ?? null;
    tlsSeg.hidden = !tls;
    setTitle(tlsSeg, tls ? `Decrypting TLS with ${tls}` : "");

    // While loading, state.file is still the previous capture.
    setText(
      fileSeg,
      !s ? "Connecting…" : s.loading ? "Loading capture…" : s.file ? `${baseName(s.file)} · ${fmtSize(s.fileSize)}` : "Ready to load or capture",
    );
    setTitle(fileSeg, s?.file ?? "");
    errSeg.hidden = !s?.loadError || s.loading;
    setTitle(errSeg, s?.loadError ?? "");

    setText(fieldSeg, fieldText);
    setTitle(fieldSeg, fieldText);
    fieldSeg.hidden = !fieldText;

    if (s?.file) {
      pktSeg.hidden = false;
      const nSel = countRanges(app.selRows);
      setText(
        pktSeg,
        `Packets: ${fmtInt(s.totalFrames)} · Displayed: ${fmtInt(s.displayedFrames)} (${fmtPct(s.displayedFrames, s.totalFrames || 1)})${nSel > 1 ? ` · Selected: ${fmtInt(nSel)}` : ""}`,
      );
      const agent = s.marks.filter((m) => m.by === "agent").length;
      markSeg.hidden = false;
      setText(markSeg, `Marked: ${fmtInt(s.marks.length)}${agent ? ` (${agent} by Claude)` : ""}`);
    } else {
      pktSeg.hidden = !s;
      setText(pktSeg, "No Packets");
      markSeg.hidden = true;
    }

    const agent = s?.agent;
    agentSeg.hidden = !agent?.attached || !agent.pending;
    setText(agentSeg, agent?.pending ? `⚠ ${fmtInt(agent.pending)} problem${agent.pending === 1 ? "" : "s"} sent to Claude` : "");

    if (s && s.capture.status !== "idle") {
      const st = captureStatusText(s);
      capSeg.hidden = false;
      capSeg.className = `sb-seg sb-cap ${st.cls}`;
      setText(capSeg, st.text);
      setTitle(capSeg, st.text);
    } else {
      capSeg.hidden = true;
    }

    connSeg.className = `sb-seg sb-conn ${app.conn}`;
    if (app.conn === "open") {
      setText(connSeg, "Connected");
      setTitle(connSeg, `Connected to the ${APP_NAME} server`);
    } else if (app.conn === "connecting") {
      setText(connSeg, "Connecting…");
      setTitle(connSeg, `Connecting to the ${APP_NAME} server`);
    } else {
      const secs = Math.max(0, Math.ceil((app.reconnectAt - Date.now()) / 1000));
      setText(connSeg, `Offline · retry in ${secs} s`);
      setTitle(connSeg, `Lost the connection to the ${APP_NAME} server. Click to retry now.`);
    }
  };

  bus.on("state", (s) => {
    syncCaptureExpert(s);
    update();
  });
  bus.on("frame", update);
  bus.on("selection", update);
  bus.on("conn", update);
  bus.on("tick", update);
  bus.on("fieldInfo", (t) => {
    fieldText = t;
    update();
  });
  update();
  return h("div", { class: "statusbar", role: "status" }, led, fileSeg, errSeg, fieldSeg, h("span", { class: "sb-flex" }), agentSeg, tlsSeg, pktSeg, markSeg, capSeg, connSeg);
}
