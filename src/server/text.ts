/** Control characters would let text from captures, plugins or other users pose as more lines of a tool result. */
export function printable(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
}
