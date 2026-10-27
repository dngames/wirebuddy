/** File > Export Specified Packets. */

import type { ExportRequest } from "../../shared/api.ts";
import { errorText } from "../api.ts";
import * as act from "../actions.ts";
import { app } from "../app.ts";
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

export function openExportDialog(): void {
  if (current?.isOpen) return;
  const s = app.state;
  if (!s?.file || s.loading) return;
  const file = s.file;
  const d = new Dialog("Export Specified Packets", { width: 600, cls: "dlg-export", resizable: false });
  current = d;

  const marked = app.marks.size;
  const sel = app.selFrame;
  let which: Which = "displayed";
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
        return null;
      },
    }),
  );

  d.body.append(
    h(
      "fieldset",
      { class: "ex-group" },
      h("legend", null, "Packet range"),
      option("all", `All captured (${fmtInt(s.totalFrames)})`),
      option("displayed", `Displayed (${fmtInt(s.displayedFrames)})${s.filter ? "" : " — no display filter applied"}`),
      option("marked", `Marked packets (${fmtInt(marked)})`, marked === 0),
      option("selected", sel !== null ? `Selected packet only (#${sel})` : "Selected packet only", sel === null),
      option("range", "Range:", false, rangeIn),
    ),
    h("div", { class: "dlg-field ex-pathrow" }, h("label", null, "Save as:", pathIn), browse),
    h("div", { class: "goto-hint" }, "The format follows the file extension: .pcapng or .pcap."),
    err,
  );

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
      const req: ExportRequest = { path, which };
      if (which === "range") req.range = range;
      if (overwrite) req.overwrite = true;
      const r = await act.exportPackets(req);
      d.close();
      toast("info", `Exported ${fmtInt(r.frames)} packet${r.frames === 1 ? "" : "s"} (${fmtSize(r.size)}) to ${baseName(r.path)}`, {
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
  d.show(radios.get("displayed"));
  // Long paths: keep the file name in view.
  pathIn.scrollLeft = pathIn.scrollWidth;
}
