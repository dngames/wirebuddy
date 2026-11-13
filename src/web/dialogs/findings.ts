/** File > Write Findings Report: the investigation's marks and comments as one Markdown file. */

import type { FindingsRequest, FindingsResult, FindingsSummary } from "../../shared/api.ts";
import { errorText, get, HttpError, post } from "../api.ts";
import { app } from "../app.ts";
import { confirmDialog, Dialog } from "../dialog.ts";
import { toast } from "../toast.ts";
import { baseName, dirName, fmtInt, fmtSize, h } from "../util.ts";
import { openFilePicker } from "./openfile.ts";

let current: Dialog | null = null;

/** The capture's folder and base name with "-findings.md". */
function defaultPath(file: string): string {
  const dir = dirName(file);
  const stem = baseName(file).replace(/\.(pcapng|pcap|cap|ntar)(\.gz|\.zst)?$/i, "");
  return `${dir ? `${dir}/` : ""}${stem}-findings.md`;
}

const count = (n: number, one: string, many: string): string => `${fmtInt(n)} ${n === 1 ? one : many}`;

export function openFindingsDialog(): void {
  if (current?.isOpen) return;
  const s = app.state;
  if (!s?.file || s.loading) return;
  const d = new Dialog("Write Findings Report", { width: 600, cls: "dlg-findings", resizable: false });
  current = d;

  const pathIn = h("input", { type: "text", class: "ex-path", spellcheck: false, value: defaultPath(s.file), attrs: { "aria-label": "Report file" } });
  const browse = h("button", { class: "btn" }, "Browse…");
  const summaryIn = h("textarea", { class: "ask-in", rows: 6, placeholder: "What was asked, what was found, what is still open (Markdown)", attrs: { "aria-label": "Summary" } });
  const listing = h("div", { class: "goto-hint" }, "Counting the marked and commented packets…");
  const err = h("div", { class: "of-err", hidden: true });
  const showErr = (m: string | null): void => {
    err.textContent = m ?? "";
    err.hidden = !m;
  };

  browse.addEventListener("click", () =>
    openFilePicker({
      title: "Write Findings Report As",
      accept: "Choose",
      kind: "any",
      storeKey: "findingsdir",
      initialPath: pathIn.value.trim() || undefined,
      onPick: (p) => {
        pathIn.value = p;
        return null;
      },
    }),
  );
  d.body.append(
    h("div", { class: "dlg-field ex-pathrow" }, h("label", null, "Save as:", pathIn), browse),
    h("div", { class: "dlg-field" }, h("label", null, "Summary (optional):", summaryIn)),
    listing,
    err,
  );
  void get<FindingsSummary>("api/findings").then(
    (r) => {
      listing.textContent = `The report lists ${count(r.marks, "marked packet", "marked packets")} and ${count(r.commented, "packet with comments", "packets with comments")}, with the capture's filter, Decode As entries and time references.`;
    },
    () => {
      listing.textContent = "The report lists the marked packets and the packets with comments.";
    },
  );

  const writeBtn = d.button("Write", () => void run(false), { primary: true });
  d.button("Cancel", () => d.close());

  const run = async (overwrite: boolean): Promise<void> => {
    const path = pathIn.value.trim();
    if (!path) return showErr("Enter the file to write");
    if (!/\.md$/i.test(path)) return showErr("Use a file name ending in .md");
    showErr(null);
    writeBtn.disabled = true;
    try {
      const req: FindingsRequest = { path, ...(summaryIn.value.trim() ? { summary: summaryIn.value } : {}), ...(overwrite ? { overwrite: true } : {}) };
      const r = await post<FindingsResult>("api/findings", req);
      d.close();
      toast("info", `Wrote the findings report ${baseName(r.path)} (${fmtSize(r.size)}: ${count(r.marks, "marked packet", "marked packets")}, ${count(r.commented, "packet", "packets")} with comments)`);
    } catch (e) {
      if (!overwrite && e instanceof HttpError && e.code === "exists") {
        writeBtn.disabled = false;
        if (await confirmDialog("Replace File?", `${baseName(path)} already exists. Replace it?`, "Replace")) await run(true);
        return;
      }
      showErr(errorText(e));
    } finally {
      writeBtn.disabled = false;
    }
  };

  d.defaultAction = () => void run(false);
  d.onClose = () => {
    current = null;
  };
  d.show(pathIn);
  pathIn.scrollLeft = pathIn.scrollWidth;
}
