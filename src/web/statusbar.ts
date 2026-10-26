/** Status bar: expert LED, file, field info, packet counts, marks, capture, connection. */

import { APP_NAME } from "./api.ts";
import { app, bus } from "./app.ts";
import { captureStatusText } from "./capture.ts";
import { maxSeverity, sevClass } from "./frame.ts";
import { baseName, fmtInt, fmtPct, fmtSize, h, setText, setTitle } from "./util.ts";
import { reconnectNow } from "./ws.ts";

export function createStatusBar(): HTMLElement {
  const led = h("span", { class: "sb-led" });
  const fileSeg = h("span", { class: "sb-seg sb-file" });
  const errSeg = h("span", { class: "sb-seg sb-err", hidden: true }, "Open failed");
  const fieldSeg = h("span", { class: "sb-seg sb-field" });
  const pktSeg = h("span", { class: "sb-seg sb-pkts" });
  const markSeg = h("span", { class: "sb-seg sb-marks" });
  const capSeg = h("span", { class: "sb-seg sb-cap" });
  const connSeg = h("button", { class: "sb-seg sb-conn", onclick: () => reconnectNow() });
  let fieldText = "";

  const update = (): void => {
    const s = app.state;
    const sev = maxSeverity(app.frame);
    led.className = `sb-led ${sev ? sevClass(sev) : "none"}`;
    setTitle(led, sev ? `Highest expert severity in this packet: ${sev}` : "No expert information for this packet");

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
      setText(pktSeg, `Packets: ${fmtInt(s.totalFrames)} · Displayed: ${fmtInt(s.displayedFrames)} (${fmtPct(s.displayedFrames, s.totalFrames || 1)})`);
      const agent = s.marks.filter((m) => m.by === "agent").length;
      markSeg.hidden = false;
      setText(markSeg, `Marked: ${fmtInt(s.marks.length)}${agent ? ` (${agent} by Claude)` : ""}`);
    } else {
      pktSeg.hidden = !s;
      setText(pktSeg, "No Packets");
      markSeg.hidden = true;
    }

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

  bus.on("state", update);
  bus.on("frame", update);
  bus.on("conn", update);
  bus.on("tick", update);
  bus.on("fieldInfo", (t) => {
    fieldText = t;
    update();
  });
  update();
  return h("div", { class: "statusbar", role: "status" }, led, fileSeg, errSeg, fieldSeg, h("span", { class: "sb-flex" }), pktSeg, markSeg, capSeg, connSeg);
}
