/** TLS decryption with a key log file (SSLKEYLOGFILE). */

import * as act from "../actions.ts";
import { app } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { toast } from "../toast.ts";
import { baseName, h, load, save } from "../util.ts";
import { openFilePicker } from "./openfile.ts";

let current: Dialog | null = null;

export function openTlsDialog(): void {
  if (current?.isOpen) return;
  const d = new Dialog("TLS Decryption", { width: 620, cls: "dlg-tls", resizable: false });
  current = d;
  const active = app.state?.tlsKeylog ?? null;

  const status = h(
    "div",
    { class: `tls-status${active ? " on" : ""}` },
    active ? "Decrypting TLS with the key log file:" : "TLS decryption is off.",
    active ? h("div", { class: "tls-path", title: active }, active) : null,
  );
  const pathIn = h("input", { type: "text", class: "ex-path", spellcheck: false, value: active ?? load<string>("tlskeylog", ""), placeholder: "/path/to/sslkeys.log", attrs: { "aria-label": "Key log file" } });
  const browse = h("button", { class: "btn" }, "Browse…");
  const err = h("div", { class: "of-err", hidden: true });
  const showErr = (m: string | null): void => {
    err.textContent = m ?? "";
    err.hidden = !m;
  };

  browse.addEventListener("click", () =>
    openFilePicker({
      title: "Choose TLS Key Log File",
      accept: "Choose",
      kind: "any",
      storeKey: "tlsdir",
      initialPath: pathIn.value.trim() || undefined,
      onPick: (p) => {
        pathIn.value = p;
        return null;
      },
    }),
  );

  d.body.append(
    status,
    h("div", { class: "dlg-field ex-pathrow" }, h("label", null, "Key log file:", pathIn), browse),
    h(
      "div",
      { class: "tls-help" },
      "Point your browser at a key log file with SSLKEYLOGFILE=… before starting it. ",
      "The capture is dissected again with those keys, so decrypted protocols (HTTP/2, HTTP …) show up in the packet list.",
    ),
    err,
  );

  const decrypt = async (): Promise<void> => {
    const p = pathIn.value.trim();
    if (!p) return showErr("Choose a key log file first");
    decryptBtn.disabled = true;
    const e = await act.setTlsKeylog(p);
    decryptBtn.disabled = false;
    if (e) return showErr(e);
    save("tlskeylog", p);
    d.close();
    toast("info", `TLS keys loaded from ${baseName(p)}`);
  };
  const off = async (): Promise<void> => {
    const e = await act.setTlsKeylog(null);
    if (e) return showErr(e);
    d.close();
    toast("info", "TLS decryption turned off");
  };

  d.button("Turn off", () => void off(), { disabled: !active, title: active ? "Stop using the key log file" : "TLS decryption is already off" });
  const decryptBtn = d.button("Decrypt", () => void decrypt(), { primary: true });
  d.button("Cancel", () => d.close());
  d.defaultAction = () => void decrypt();
  d.onClose = () => {
    current = null;
  };
  d.show(pathIn);
  pathIn.setSelectionRange(pathIn.value.length, pathIn.value.length);
  pathIn.scrollLeft = pathIn.scrollWidth;
}
