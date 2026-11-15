/** View › Time Display Format, and the same list in the packet list's column header menu. */

import { TIME_FORMATS } from "../shared/timeformat.ts";
import * as act from "./actions.ts";
import { app } from "./app.ts";
import type { MenuItem } from "./menu.ts";

/** One entry per format, the one the Time column shows checked. */
export function timeFormatItems(): MenuItem[] {
  const now = app.state?.timeFormat ?? "relative";
  return TIME_FORMATS.map((f) => ({ label: f.label, checked: f.id === now, action: () => void act.setTimeFormat(f.id) }));
}
