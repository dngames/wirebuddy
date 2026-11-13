/** What a capture on loopback says of WireBuddy's own traffic, which it leaves out (see CaptureState.leftOutPort). */
export function leftOutText(port: number): string {
  return `WireBuddy's own traffic (TCP port ${port}) is left out`;
}
