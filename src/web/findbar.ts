/** Edit > Find Packet: a bar under the display filter, like Wireshark's. */

import { errorText } from "./api.ts";
import * as act from "./actions.ts";
import { icon } from "./icons.ts";
import { focusPacketList } from "./packetlist.ts";
import { h, keyLabel, load, save } from "./util.ts";

type Mode = "filter" | "string" | "hex";

const PLACEHOLDER: Record<Mode, string> = {
  filter: "Display filter, e.g. http.response.code == 404",
  string: "Text in the packet bytes",
  hex: "Bytes in hex, e.g. 00:1b:21 or 001b21",
};

let bar: HTMLElement;
let modeSel: HTMLSelectElement;
let input: HTMLInputElement;
let caseBox: HTMLInputElement;
let caseLbl: HTMLElement;
let status: HTMLElement;
/** Filter of the last search, for Find Next / Previous while the bar is closed. */
let last: string | null = null;
let busy = false;

/** Display filter for a search; throws on malformed hex. */
export function findFilter(mode: Mode, text: string, caseSensitive: boolean): string {
  if (mode === "filter") return text;
  if (mode === "hex") {
    const hex = text.replace(/0x/gi, "").replace(/[\s:.-]/g, "");
    if (!/^([0-9a-f]{2})+$/i.test(hex)) throw new Error("Enter bytes as pairs of hex digits, e.g. 00:1b:21");
    const bytes = hex.match(/../g)!;
    // A lone "47" would read as a number; "47:" is a one-byte string
    return `frame contains ${bytes.length === 1 ? `${bytes[0]}:` : bytes.join(":")}`;
  }
  const literal = (t: string): string => `"${t.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  if (caseSensitive) return `frame contains ${literal(text)}`;
  return `frame matches ${literal(`(?i)${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`)}`;
}

function setStatus(text: string, error = false): void {
  status.textContent = text;
  status.classList.toggle("error", error);
}

async function search(filter: string, dir: 1 | -1): Promise<void> {
  if (busy) return;
  busy = true;
  setStatus("Searching…");
  try {
    const r = await act.findPacket(filter, dir);
    if (r.frame === null) setStatus("No packet matched", true);
    else setStatus(r.wrapped ? `Packet ${r.frame} · search wrapped around` : `Packet ${r.frame}`);
  } catch (e) {
    setStatus(errorText(e), true);
  } finally {
    busy = false;
  }
}

/** What to find: strings as typed, spaces included. */
function query(): string {
  return modeSel.value === "string" ? input.value : input.value.trim();
}

async function run(dir: 1 | -1): Promise<void> {
  const text = query();
  if (!text) {
    setStatus("Enter what to find", true);
    return;
  }
  let filter: string;
  try {
    filter = findFilter(modeSel.value as Mode, text, caseBox.checked);
  } catch (e) {
    setStatus((e as Error).message, true);
    return;
  }
  last = filter;
  await search(filter, dir);
}

export function openFindBar(): void {
  bar.hidden = false;
  input.focus();
  input.select();
}

function closeFindBar(): void {
  bar.hidden = true;
  focusPacketList();
}

/** Edit > Find Next / Find Previous. */
export async function findAgain(dir: 1 | -1): Promise<void> {
  if (!bar.hidden && query()) await run(dir);
  else if (last !== null) await search(last, dir);
  else openFindBar();
}

export function createFindBar(): HTMLElement {
  const mode = load<Mode>("findmode", "filter");
  modeSel = h(
    "select",
    { class: "fd-mode", attrs: { "aria-label": "Search by" } },
    h("option", { value: "filter" }, "Display filter"),
    h("option", { value: "string" }, "String"),
    h("option", { value: "hex" }, "Hex value"),
  );
  modeSel.value = PLACEHOLDER[mode] ? mode : "filter";
  input = h("input", { type: "text", class: "fd-input", spellcheck: false, attrs: { "aria-label": "Find" } });
  caseBox = h("input", { type: "checkbox", checked: load<boolean>("findcase", false) });
  caseLbl = h("label", { class: "fd-case" }, caseBox, "Case sensitive");
  status = h("span", { class: "fd-status", role: "status" });
  const findBtn = h("button", { class: "btn primary fd-btn", title: `Find the next match (Enter, ${keyLabel("F3")})` }, "Find");
  const prevBtn = h("button", { class: "btn fd-btn", title: `Find the previous match (${keyLabel("Shift+Enter")}, ${keyLabel("Shift+F3")})` }, "Previous");
  const closeBtn = h("button", { class: "tb-mini", title: "Close (Esc)", attrs: { "aria-label": "Close the find bar" } }, icon("x"));

  const syncMode = (): void => {
    const m = modeSel.value as Mode;
    input.placeholder = PLACEHOLDER[m];
    input.classList.toggle("mono", m !== "string");
    caseLbl.hidden = m !== "string";
    setStatus("");
  };
  modeSel.addEventListener("change", () => {
    save("findmode", modeSel.value);
    syncMode();
    input.focus();
  });
  caseBox.addEventListener("change", () => save("findcase", caseBox.checked));
  input.addEventListener("input", () => setStatus(""));
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      void run(e.shiftKey ? -1 : 1);
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      closeFindBar();
    }
  });
  findBtn.addEventListener("click", () => void run(1));
  prevBtn.addEventListener("click", () => void run(-1));
  closeBtn.addEventListener("click", closeFindBar);
  syncMode();

  bar = h("div", { class: "findbar", hidden: true, role: "search" }, h("span", { class: "fd-lbl" }, "Find:"), modeSel, input, caseLbl, findBtn, prevBtn, status, closeBtn);
  return bar;
}
