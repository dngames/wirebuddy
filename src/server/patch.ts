/**
 * The top-level fields of `next` that differ from `prev`, each as the JSON of its new value.
 * A value is compared by reference first (an unchanged one keeps its identity from one state to the next,
 * so big ones are never serialised) and by its JSON only when the reference changed, so a value rebuilt equal isn't sent.
 * `jsonOf` serialises one value.
 */
export function changedFields(prev: object, next: object, jsonOf: (value: unknown) => string): Record<string, string> {
  const out: Record<string, string> = {};
  const was = prev as Record<string, unknown>;
  for (const [key, value] of Object.entries(next)) {
    if (value === was[key]) continue;
    const json = jsonOf(value);
    // Primitives equal by value are the same reference; two objects are the same when they read the same
    if (typeof value === "object" && value !== null && typeof was[key] === "object" && was[key] !== null && json === jsonOf(was[key])) continue;
    out[key] = json;
  }
  return out;
}

/** The text of a patch message: `fields` as `changedFields` gives them, spliced in without parsing them again. */
export function patchMessage(seq: number, fields: Record<string, string>): string {
  return `{"type":"patch","seq":${seq},"patch":{${Object.entries(fields).map(([k, json]) => `${JSON.stringify(k)}:${json}`).join(",")}}}`;
}
