/**
 * The Time column's display format (View › Time Display Format, as Wireshark's
 * names have it). sharkd gives the time in the one format its Time column has;
 * for the others the viewer asks it for the field that carries the time, and
 * these functions turn that field's text into the column's.
 */

export type TimeFormat = "relative" | "delta-displayed" | "delta-captured" | "time-of-day" | "date-time" | "utc-time-of-day" | "utc-date-time";

/** The formats in the order of the menu, with the menu's words. */
export const TIME_FORMATS: { id: TimeFormat; label: string }[] = [
  { id: "relative", label: "Seconds Since Beginning of Capture" },
  { id: "delta-displayed", label: "Seconds Since Previous Displayed Packet" },
  { id: "delta-captured", label: "Seconds Since Previous Captured Packet" },
  { id: "time-of-day", label: "Time of Day" },
  { id: "date-time", label: "Date and Time of Day" },
  { id: "utc-time-of-day", label: "UTC Time of Day" },
  { id: "utc-date-time", label: "UTC Date and Time of Day" },
];

export function isTimeFormat(value: unknown): value is TimeFormat {
  return TIME_FORMATS.some((f) => f.id === value);
}

export function timeFormatLabel(format: TimeFormat): string {
  return TIME_FORMATS.find((f) => f.id === format)!.label;
}

/** The field sharkd gives the time of `format` in; null for the Time column's own text (seconds since the beginning or the time reference). */
export function timeField(format: TimeFormat): string | null {
  switch (format) {
    case "relative":
      return null;
    case "delta-displayed":
      return "frame.time_delta_displayed";
    case "delta-captured":
      return "frame.time_delta";
    case "time-of-day":
    case "date-time":
      return "frame.time";
    default:
      return "frame.time_utc";
  }
}

/** The decimals of a time in the Time column's own text ("0.000123" is 6), null where it has none ("*REF*"). */
export function timeDigits(text: string): number | null {
  const m = /^-?\d+\.(\d+)$/.exec(text);
  return m ? m[1].length : null;
}

/**
 * The Time column's text of `format` from the `value` of its field with
 * `digits` decimals (the capture's own, as its Time column shows them). A
 * first packet has no previous one: its delta reads 0, unless `exact` is false
 * (rows of a slice, which may lack the one before), then it stays empty.
 */
export function timeText(format: TimeFormat, value: string, digits: number, exact: boolean): string {
  const fraction = (f: string): string => (digits ? `.${f.padEnd(digits, "0").slice(0, digits)}` : "");
  if (format === "delta-displayed" || format === "delta-captured") {
    if (!value) return exact ? `0${fraction("")}` : "";
    const m = /^(-?\d+)(?:\.(\d+))?$/.exec(value);
    return m ? `${m[1]}${fraction(m[2] ?? "")}` : "";
  }
  // 2026-10-27T02:36:03.801146840+0530, or ...Z
  const m = /^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)(?:\.(\d+))?/.exec(value);
  if (!m) return "";
  const time = `${m[2]}${fraction(m[3] ?? "")}`;
  return format === "date-time" || format === "utc-date-time" ? `${m[1]} ${time}` : time;
}
