/** File > Export Specified Packets. */

import type { ExportRequest } from "../../shared/api.ts";
import { countRanges, inRanges } from "../../shared/ranges.ts";
import { errorText } from "../api.ts";
import * as act from "../actions.ts";
import { app, knownFrames } from "../app.ts";
import { confirmDialog, Dialog } from "../dialog.ts";
import { toast } from "../toast.ts";
import { baseName, dirName, fmtInt, fmtSize, h } from "../util.ts";
import { openFilePicker } from "./openfile.ts";

type Which = ExportRequest["which"];

let current: Dialog | null = null;

function defaultPath(file: string, which: Which): string {
  const dir = dirName(file);
  const stem = baseName(file).replace(/\.(pcapng|pcap|cap|ntar)(\.gz)?$/i, "");
  return `${dir ? `${dir}/` : ""}${stem}_${which}.pcapng`;
}

/** Opens the dialog with `initial` chosen (File > Save As: "all"). */
export function openExportDialog(initial: Which = "displayed"): void {
  if (current?.isOpen) return;
  const s = app.state;
  if (!s?.file || s.loading) return;
  const file = s.file;
  const d = new Dialog("Export Specified Packets", { width: 600, cls: "dlg-export", resizable: false });
  current = d;

  const marked = app.marks.size;
  const sel = app.selFrame;
  const nSel = countRanges(app.selRows);
  let which: Which = initial === "selected" && !nSel && sel === null ? "displayed" : initial;
  let pathEdited = false;

  const radios = new Map<Which, HTMLInputElement>();
  const option = (w: Which, label: string, disabled = false, extra: HTMLElement | null = null): HTMLElement => {
    const r = h("input", { type: "radio", name: "ex-which", value: w, checked: w === which, disabled });
    radios.set(w, r);
    r.addEventListener("change", () => {
      if (r.checked) setWhich(w);
    });
    return h("label", { class: `ex-opt${disabled ? " disabled" : ""}` }, r, h("span", null, label), extra);
  };
  const rangeIn = h("input", { type: "text", class: "ex-range", placeholder: "e.g. 1-10,25", spellcheck: false, attrs: { "aria-label": "Packet range" } });
  const pathIn = h("input", { type: "text", class: "ex-path", spellcheck: false, value: defaultPath(file, which), attrs: { "aria-label": "Output file" } });
  const browse = h("button", { class: "btn" }, "Browse…");
  const err = h("div", { class: "of-err", hidden: true });
  const commentsBox = h("input", { type: "checkbox", checked: true });
  const commentsOpt = h("label", { class: "ex-opt", hidden: marked === 0 }, commentsBox, h("span", null, "Marks and their notes as packet comments"));
  const edits = s.commentEdits;
  const editedNote = h("div", { class: "goto-hint", hidden: !edits });
  // pcap has no packet comments
  const syncComments = (): void => {
    const pcap = /\.pcap$/i.test(pathIn.value.trim());
    commentsBox.disabled = pcap;
    commentsOpt.classList.toggle("disabled", pcap);
    const packets = `${fmtInt(edits)} packet${edits === 1 ? "" : "s"}`;
    editedNote.textContent = pcap ? `pcap holds no packet comments: the ones edited in ${packets} are left out.` : `Packet comments go along as edited (${packets} not exported yet).`;
    editedNote.classList.toggle("ex-warn", pcap);
  };

  const showErr = (m: string | null): void => {
    err.textContent = m ?? "";
    err.hidden = !m;
  };

  const setWhich = (w: Which): void => {
    which = w;
    const r = radios.get(w);
    if (r && !r.checked) r.checked = true;
    if (!pathEdited) {
      pathIn.value = defaultPath(file, w);
      pathIn.scrollLeft = pathIn.scrollWidth;
    }
    showErr(null);
  };

  rangeIn.addEventListener("focus", () => setWhich("range"));
  pathIn.addEventListener("input", () => {
    pathEdited = true;
    syncComments();
  });
  browse.addEventListener("click", () =>
    openFilePicker({
      title: "Export As",
      accept: "Choose",
      kind: "capture",
      storeKey: "exportdir",
      initialPath: pathIn.value.trim() || undefined,
      onPick: (p) => {
        pathIn.value = p;
        pathEdited = true;
        syncComments();
        return null;
      },
    }),
  );

  d.body.append(
    h(
      "fieldset",
      { class: "ex-group" },
      h("legend", null, "Packet range"),
      option("all", `All captured (${fmtInt(knownFrames(s))})`),
      // Provisional matches of a live capture's newest packets aren't exported
      option("displayed", `Displayed (${fmtInt(s.filter ? s.displayedFrames : knownFrames(s))})${s.filter ? (s.tail?.displayed ? ` — ${fmtInt(s.tail.displayed)} provisional left out` : "") : " — no display filter applied"}`),
      option("marked", `Marked packets (${fmtInt(marked)})`, marked === 0),
      // The server exports the selected rows, which need not include the current packet
      nSel > 1 || (nSel === 1 && !inRanges(app.selRows, app.selIndex))
        ? option("selected", `Selected packets only (${fmtInt(nSel)})`)
        : option("selected", sel !== null ? `Selected packet only (#${sel})` : "Selected packet only", sel === null),
      option("range", "Range:", false, rangeIn),
    ),
    h("div", { class: "dlg-field ex-pathrow" }, h("label", null, "Save as:", pathIn), browse),
    h("div", { class: "goto-hint" }, "The format follows the file extension: .pcapng or .pcap."),
    commentsOpt,
    editedNote,
    err,
  );
  syncComments();

  const exportBtn = d.button("Export", () => void run(false), { primary: true });
  d.button("Cancel", () => d.close());

  const run = async (overwrite: boolean): Promise<void> => {
    const path = pathIn.value.trim();
    const range = rangeIn.value.trim();
    if (!path) return showErr("Enter the file to export to");
    if (!/\.(pcapng|pcap)$/i.test(path)) return showErr("Use a file name ending in .pcapng or .pcap");
    if (which === "range" && !/^\s*\d+(\s*-\s*\d+)?(\s*,\s*\d+(\s*-\s*\d+)?)*\s*$/.test(range)) return showErr("Enter a range like 1-10,25");
    showErr(null);
    exportBtn.disabled = true;
    try {
      // The server exports the selection it knows: send a pending one first
      if (which === "selected" && !(await act.flushSelection())) {
        showErr("The packet list changed; select the packets again");
        return;
      }
      const req: ExportRequest = { path, which };
      if (which === "range") req.range = range;
      if (overwrite) req.overwrite = true;
      if (commentsBox.checked && !commentsBox.disabled) req.markComments = true;
      const r = await act.exportPackets(req);
      d.close();
      const marks = r.comments ? `, ${fmtInt(r.comments)} mark${r.comments === 1 ? "" : "s"} as comments` : "";
      const comments = `${marks}${r.edited ? `, edited comments of ${fmtInt(r.edited)} packet${r.edited === 1 ? "" : "s"}` : ""}`;
      const left = r.leftOut ? `; ${fmtInt(r.leftOut)} provisional packet${r.leftOut === 1 ? "" : "s"} left out` : "";
      toast("info", `Exported ${fmtInt(r.frames)} packet${r.frames === 1 ? "" : "s"} (${fmtSize(r.size)}${comments}) to ${baseName(r.path)}${left}`, {
        label: "Open",
        run: () =>
          void act.openFile(r.path).then((e) => {
            if (e) toast("error", `Can't open ${baseName(r.path)}: ${e}`);
          }),
      });
    } catch (e) {
      const m = errorText(e);
      if (!overwrite && /exist/i.test(m)) {
        exportBtn.disabled = false;
        if (await confirmDialog("Replace File?", `${baseName(path)} already exists. Replace it?`, "Replace")) await run(true);
        return;
      }
      showErr(m);
    } finally {
      exportBtn.disabled = false;
    }
  };

  d.defaultAction = () => void run(false);
  d.onClose = () => {
    current = null;
  };
  d.show(radios.get(which));
  // Long paths: keep the file name in view.
  pathIn.scrollLeft = pathIn.scrollWidth;
}
