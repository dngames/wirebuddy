/** How the server and the UI name a Decode As entry. */

import type { DecodeAsEntry } from "./api.ts";

/** "udp.port 50000 → rtp". */
export function entryText(e: DecodeAsEntry): string {
  return `${e.table} ${e.value} → ${e.protocol}`;
}
