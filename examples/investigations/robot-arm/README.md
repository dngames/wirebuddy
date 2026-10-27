# Robot arm: why does it stutter?

An investigation to try WireBuddy on, with the agent: a pick-and-place arm that moves in jerks.
Everything runs on your machine over loopback, an emulated arm controller and the control app
that drives it.

| File | What it is |
|---|---|
| `device.mjs` | The arm controller, emulated: ARMC v1 commands on TCP port 7700, telemetry to UDP port 7701 at 100 Hz |
| `app.mjs` | The cell's control app: homes the arm, streams MOVE commands along a trajectory at 50 Hz, reports how well the arm followed |
| `PROTOCOL.md` | The controller vendor's protocol document |
| `solution/` | Spoilers, see [Solution](#solution) |

## The symptom

The app is meant to send the arm a new target every 20 ms, each one acknowledged by the controller
before the next. The arm's moves come in jerks instead, and the app's report shows it reaching less
than half the rate. The vendor says their controller answers every command in under a millisecond,
and the processing time it reports in each ACK agrees.

## Run it

Node 22 or later, no dependencies. From the repository root, the controller in a terminal of its
own (or in the background with `&`), then the app:

```bash
node examples/investigations/robot-arm/device.mjs
node examples/investigations/robot-arm/app.mjs
```

```
connected to ARMC controller at 127.0.0.1:7700 (ping 1.52 ms)
at start pose, streaming the trajectory for 6 s at 50 Hz

Trajectory report
  MOVE commands     133 sent, 22.1/s achieved (requested 50/s)
  deadlines missed  167 of 300 command slots
  ACK latency       p50 44.0 ms, p95 48.1 ms, max 48.2 ms
  controller time   p50 20 µs (reported in the ACKs)
  tracking error    max 7.7° (j2), rms 3.5°

WARNING: command rate 22.1/s is below the required 50/s, motion will not be smooth
```

Both take `--port` (TCP, default 7700) and `--telemetry` (UDP, default 7701); the app also takes
`--seconds` (default 6) and `--rate` (commands per second, default 50). The controller runs until
you stop it with Ctrl+C.

## Investigate it with the agent

Register WireBuddy with Claude Code and give `dumpcap` its capture permissions (see the main
[README](../../../README.md)), start the controller, then ask:

> The robot arm stutters. Our control app, examples/investigations/robot-arm/app.mjs, should send
> the arm controller 50 MOVE commands a second, but gets about 22 through and the arm moves in
> jerks. The vendor says the controller answers every command in under a millisecond; their protocol
> document is examples/investigations/robot-arm/PROTOCOL.md. The controller is running on port 7700.
> Capture the traffic while the app runs and find out why.

To make the agent work from the traffic alone, ask it not to read `app.mjs` until it has an answer
from the capture.

### What to expect

1. The agent captures on `lo` with a capture filter for the controller's ports, runs the app and
   stops the capture when the app is done.
2. The TCP connection and the UDP stream show up as undecoded data. The agent writes a Lua
   dissector for ARMC from `PROTOCOL.md`, tests it against the capture and reloads the view: MOVEs,
   ACKs and telemetry get their fields, filters and columns.
3. It measures in the capture how long the controller really takes to answer, and looks for where
   the rest of the app's 44 ms goes.
4. It may write a panel plotting the telemetry, target and actual joint angles over time, where the
   jerks show.
5. It names the cause, shows it in the packets, then in the code, and proposes a fix. Apply it,
   run the app again and let the agent capture once more to confirm.

## Tests

`npm run test:examples` runs the controller and the app over loopback without a capture: it checks
the controller against `PROTOCOL.md`, that the app as shipped stays under 35 commands a second with
ACKs over 30 ms, and that `solution/fix.diff` brings it over 45 with ACKs under 5 ms.
`npm run test:live` also captures both on `lo` and checks the packets.

## Solution

**Spoilers from here on.**

In the capture, every MOVE leaves the app as two TCP segments: the 8-byte header, and about 40 ms
later the 14-byte payload. In between, the controller's TCP stack acknowledges the header with an
empty segment. Once the payload is in, the controller's ARMC ACK follows within microseconds, just
as the vendor said. PING, HOME and STOP, which have no payload, are answered at once.

`ArmClient.send()` writes the header and the payload with two `socket.write()` calls. Node leaves
Nagle's algorithm on for sockets from `net.connect`, so the kernel sends the header at once but
holds the small payload back until the header is acknowledged. The controller, holding half a
message, has no reply to send that acknowledgement with, so its kernel delays it: delayed ACK, at
least 40 ms on Linux. Every command costs about 44 ms, the app gets 22 a second through, misses more
than half its 20 ms slots, and the arm reaches each target early and stands waiting for the next.

The fix writes each message in one call, [`solution/fix.diff`](solution/fix.diff):

```bash
git apply examples/investigations/robot-arm/solution/fix.diff
```

```
Trajectory report
  MOVE commands     300 sent, 50.2/s achieved (requested 50/s)
  deadlines missed  0 of 300 command slots
  ACK latency       p50 0.3 ms, p95 0.4 ms, max 0.5 ms
  controller time   p50 13 µs (reported in the ACKs)
  tracking error    max 0.9° (j1), rms 0.4°
```

`socket.setNoDelay(true)` removes the wait as well, but still sends each MOVE as two segments; one
write per message fixes it with Nagle on or off.

`solution/armc/` is a WireBuddy extension as the agent might write it: the ARMC dissector and a
panel plotting the telemetry. Copy it into `~/.local/share/wirebuddy/extensions/` to compare.
