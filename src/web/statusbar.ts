/** Status bar: expert LED, file, field info, panel offers, TLS keys, Decode As, extensions, packet counts, provisional packets, marks, capture, connection. */

import type { ExpertItem, ExpertSeverity, PanelOffer, ViewState } from "../shared/api.ts";
import { entryText } from "../shared/decodeas.ts";
import { countRanges } from "../shared/ranges.ts";
import { APP_NAME, get } from "./api.ts";
import { agentName, app, bus, knownFrames } from "./app.ts";
import { captureStatusText } from "./capture.ts";
import { decodeAsMenu } from "./dialogs/decodeas.ts";
import { maxItemSeverity, openExpertDialog } from "./dialogs/expert.ts";
import { openExtensionsDialog } from "./dialogs/extensions.ts";
import { openTlsDialog } from "./dialogs/tls.ts";
import { maxSeverity, sevClass } from "./frame.ts";
import { icon } from "./icons.ts";
import { toggleMenuAt } from "./menu.ts";
import { dismissOffer, openPanel } from "./panels.ts";
import { baseName, fmtInt, fmtPct, fmtSize, h, setText, setTitle } from "./util.ts";
import { reconnectNow } from "./ws.ts";

/** Panel offers shown at once. */
const MAX_OFFERS = 3;

export function createStatusBar(): HTMLElement {
  const led = h("button", { class: "sb-led", attrs: { "aria-label": "Expert information" }, onclick: () => openExpertDialog() });
  const tlsSeg = h("button", { class: "sb-seg sb-tls", hidden: true, onclick: () => openTlsDialog() }, icon("lock"), "TLS keys");
  const daSeg = h("button", { class: "sb-seg sb-tls sb-da", hidden: true, onclick: () => toggleMenuAt(daSeg, decodeAsMenu) });
  const extText = h("span");
  const extSeg = h("button", { class: "sb-seg sb-tls sb-ext", hidden: true, onclick: () => openExtensionsDialog() }, icon("puzzle"), extText);
  const fileSeg = h("span", { class: "sb-seg sb-file" });
  const errSeg = h("span", { class: "sb-seg sb-err", hidden: true }, "Open failed");
  const fieldSeg = h("span", { class: "sb-seg sb-field" });
  const pktSeg = h("span", { class: "sb-seg sb-pkts" });
  const liveSeg = h("span", { class: "sb-seg sb-live", hidden: true });
  const markSeg = h("span", { class: "sb-seg sb-marks" });
  const capSeg = h("span", { class: "sb-seg sb-cap" });
  const connSeg = h("button", { class: "sb-seg sb-conn", onclick: () => reconnectNow() });
  const offersSeg = h("span", { class: "sb-offers", hidden: true });
  let offersKey = "";
  const agentSeg = h(
    "span",
    {
      class: "sb-seg sb-agent",
      hidden: true,
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
    const key = `${s.instance}|${s.file}|${s.fileSize}|${s.totalFrames}|${s.tlsKeylog ?? ""}|${s.extensions.revision}|${s.epoch}`;
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
    const da = s?.decodeAs.entries ?? [];
    daSeg.hidden = !da.length;
    setText(daSeg, `Decode As: ${da.length}`);
    setTitle(daSeg, `Decode As, for every capture until ${APP_NAME} exits:\n${da.map((e) => `${entryText(e)} (by ${e.by === "user" ? "you" : agentName()})`).join("\n")}\nClick to remove entries.`);
    const ext = s?.extensions;
    extSeg.hidden = !ext || (!ext.active && !ext.failing);
    extSeg.classList.toggle("failing", !!ext?.failing);
    setText(extText, ext?.failing ? `${ext.failing} extension${ext.failing === 1 ? "" : "s"} failing` : `${ext?.active ?? 0} extension${ext?.active === 1 ? "" : "s"}`);
    setTitle(extSeg, "Lua extensions decoding this capture. Click for Analyze › Extensions.");

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
      const known = knownFrames(s);
      const shown = s.displayedFrames + (s.tail?.displayed ?? 0);
      setText(pktSeg, `Packets: ${fmtInt(known)} · Displayed: ${fmtInt(shown)} (${fmtPct(shown, known || 1)})${nSel > 1 ? ` · Selected: ${fmtInt(nSel)}` : ""}`);
      const agent = s.marks.filter((m) => m.by === "agent").length;
      markSeg.hidden = false;
      setText(markSeg, `Marked: ${fmtInt(s.marks.length)}${agent ? ` (${agent} by ${agentName()})` : ""}`);
    } else {
      pktSeg.hidden = !s;
      setText(pktSeg, "No Packets");
      markSeg.hidden = true;
    }

    // A live capture's packets after the last full read
    const tail = s?.file ? s.tail : null;
    liveSeg.hidden = !tail?.frames;
    liveSeg.classList.toggle("paused", !!tail?.paused);
    if (tail?.frames) {
      const secs = Math.max(1, Math.round(tail.readMs / 1000));
      const when = {
        read: `exact after the next full read (≈${secs} s)`,
        stop: "exact once the capture stops",
        reading: "exact once the full read under way finishes",
        reload: "exact once read in full (View › Reload)",
      }[tail.exactAfter];
      const unfiltered = tail.unfiltered ? ` · ${fmtInt(tail.unfiltered)} not filtered yet` : "";
      setText(liveSeg, `${fmtInt(tail.frames)} provisional · ${when}${unfiltered}`);
      const held = tail.held ? `\nThe display filter lists them only once read in full: ${tail.held}.` : "";
      const paused = tail.paused ? `\nFull reads wait: ${tail.paused}.` : "";
      setTitle(liveSeg, `Packets that arrived after WireBuddy last read the whole capture (it takes about ${secs} s), read from the newest packets with their connections' start. Shown in italics; the next full read makes them exact.${held}${paused}`);
    }

    // Panels whose offer matches the capture: a chip opens one, × hides it for this file
    const offers: PanelOffer[] = s?.panelOffers.slice(0, MAX_OFFERS) ?? [];
    const key = JSON.stringify(offers);
    if (key !== offersKey) {
      offersKey = key;
      offersSeg.hidden = !offers.length;
      offersSeg.replaceChildren(
        ...offers.map((o) =>
          h(
            "span",
            { class: "sb-seg sb-offer" },
            h("button", { class: "sb-offer-open", title: `Open the panel of the extension ${o.label}`, onclick: () => void openPanel(o.name) }, icon("puzzle"), `${o.label}: ${o.text} ▸`),
            h("button", { class: "sb-offer-x", title: "Don't offer it again for this capture", attrs: { "aria-label": `Dismiss ${o.label}` }, onclick: () => void dismissOffer(o.name) }, icon("x")),
          ),
        ),
      );
    }

    const agent = s?.agent;
    agentSeg.hidden = !agent?.attached || !agent.pending;
    const who = agentName();
    setText(agentSeg, agent?.pending ? `⚠ ${fmtInt(agent.pending)} problem${agent.pending === 1 ? "" : "s"} sent to ${who}` : "");
    setTitle(agentSeg, `Problems ${who} gets with its next WireBuddy call, or at once while it watches the viewer. If nothing happens, ask ${who} in the chat.`);

    if (s && s.capture.status !== "idle") {
      const st = captureStatusText(s);
      const c = s.capture;
      // The file being written, where, and how many so far (new files automatically)
      const file = c.currentFile ?? c.files[c.files.length - 1] ?? null;
      const where = file ? `\nWriting ${baseName(file)} in ${c.dir}${c.files.length > 1 ? ` · ${c.files.length} files` : ""}` : "";
      capSeg.hidden = false;
      capSeg.className = `sb-seg sb-cap ${st.cls}`;
      setText(capSeg, st.text);
      setTitle(capSeg, st.text + where);
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
  return h("div", { class: "statusbar", role: "status" }, led, fileSeg, errSeg, fieldSeg, h("span", { class: "sb-flex" }), offersSeg, agentSeg, tlsSeg, daSeg, extSeg, pktSeg, liveSeg, markSeg, capSeg, connSeg);
}
