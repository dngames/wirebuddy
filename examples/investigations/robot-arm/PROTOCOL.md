# ARMC host interface, protocol version 1

Host interface of the ARMC three-axis arm controller: how a cell controller or PC commands the arm
and reads back its position.

| Channel | Transport | Default port | Direction |
|---|---|---|---|
| Commands | TCP, the controller listens | 7700 | host → controller, replies controller → host |
| Telemetry | UDP datagrams | 7701 | controller → host, 100 Hz |

Both ports can be configured on the controller. The telemetry destination address is configured on
the controller as well; it does not depend on the TCP connection.

## 1. Conventions

- All integers are big-endian (network byte order).
- Joint angles are signed 32-bit integers in millidegrees (1° = 1000). 0 is the home position of a
  joint.
- Speeds are unsigned 16-bit integers in degrees per second.
- `u8`, `u16`, `u32` are unsigned, `i32` is signed (two's complement).

## 2. Command channel

The host opens one TCP connection to the controller and sends requests. The controller answers every
request with exactly one reply carrying the request's sequence number. Requests are handled on
arrival; the processing time, typically well below 100 µs, is reported in every ACK.

A host may send its next request before the reply to the previous one has arrived. Requests are
executed in the order they are received.

### 2.1 Message layout

Every message, in both directions, is an 8-byte header followed by a payload of 0 to 64 bytes.

| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 2 | bytes | magic | `0x41 0x4D` ("AM") |
| 2 | 1 | u8 | version | Protocol version, `1` |
| 3 | 1 | u8 | type | Message type, see 2.2 |
| 4 | 2 | u16 | seq | Sequence number chosen by the host; a reply repeats the request's |
| 6 | 2 | u16 | length | Payload length in bytes, without the header |
| 8 | length | | payload | Depends on the message type |

The host should count `seq` up by one per request and wrap from 65535 to 0.

### 2.2 Message types

| Type | Name | Direction | Payload | Reply |
|---|---|---|---|---|
| `0x01` | MOVE | host → controller | 14 bytes | ACK or NACK |
| `0x02` | HOME | host → controller | none | ACK or NACK |
| `0x03` | STOP | host → controller | none | ACK or NACK |
| `0x10` | PING | host → controller | none | PONG or NACK |
| `0x81` | ACK | controller → host | 4 bytes | |
| `0x82` | NACK | controller → host | 1 + n bytes | |
| `0x90` | PONG | controller → host | none | |

### 2.3 MOVE (0x01)

Sets a new target for all three joints. The controller moves every joint toward its target at no more
than the given speed. A MOVE replaces the current target at once, also while the arm is still moving
toward it: the controller does not queue targets. To follow a path, send its points one after the
other.

| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 4 | i32 | j1 | Target of joint 1 (base), millidegrees |
| 4 | 4 | i32 | j2 | Target of joint 2 (shoulder), millidegrees |
| 8 | 4 | i32 | j3 | Target of joint 3 (elbow), millidegrees |
| 12 | 2 | u16 | speed | Maximum joint speed, deg/s, 1 to 180 |

A target outside the joint limits (section 4) or a speed outside 1 to 180 is refused with NACK 5;
the arm keeps its previous target.

### 2.4 HOME (0x02)

Moves all joints to 0 at 60 deg/s. No payload.

### 2.5 STOP (0x03)

Stops the arm where it is: the current position becomes the target. No payload.

### 2.6 PING (0x10)

Checks the connection. No payload; the controller answers with PONG.

### 2.7 ACK (0x81)

The request was accepted.

| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 1 | u8 | status | `0` = ok |
| 1 | 1 | u8 | queue | Targets not reached yet: `0` when the arm stands at its target, `1` while it moves |
| 2 | 2 | u16 | time | Controller processing time of the request, µs |

### 2.8 NACK (0x82)

The request was refused and had no effect.

| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 1 | u8 | code | Error code, see the table |
| 1 | length − 1 | UTF-8 | reason | Human-readable reason, not terminated |

| Code | Meaning |
|---|---|
| 1 | Bad magic. The controller closes the connection after this NACK. |
| 2 | Unsupported protocol version |
| 3 | Unknown message type |
| 4 | Bad payload length for the type. A length over 64 also closes the connection. |
| 5 | Value out of range (joint limit or speed) |

### 2.9 PONG (0x90)

Answer to PING. No payload.

## 3. Telemetry

The controller sends one datagram every 10 ms (100 Hz) to the configured telemetry address, whether a
host is connected or not. A datagram is 36 bytes:

| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 2 | bytes | magic | `0x41 0x54` ("AT") |
| 2 | 1 | u8 | version | `1` |
| 3 | 1 | u8 | flags | bit 0: moving, bit 1: target reached, other bits 0 |
| 4 | 4 | u32 | seq | Datagram counter, +1 per datagram |
| 8 | 4 | u32 | time | Controller time since power-on, ms |
| 12 | 4 | i32 | j1 | Actual position of joint 1, millidegrees |
| 16 | 4 | i32 | j2 | Actual position of joint 2, millidegrees |
| 20 | 4 | i32 | j3 | Actual position of joint 3, millidegrees |
| 24 | 4 | i32 | target j1 | Current target of joint 1, millidegrees |
| 28 | 4 | i32 | target j2 | Current target of joint 2, millidegrees |
| 32 | 4 | i32 | target j3 | Current target of joint 3, millidegrees |

"Moving" is set when any joint moved during the last cycle, "target reached" when all joints stand at
their targets. A gap in `seq` means datagrams were lost.

## 4. Joint limits

| Joint | Name | Minimum | Maximum |
|---|---|---|---|
| j1 | base | −170° | +170° |
| j2 | shoulder | −90° | +90° |
| j3 | elbow | −135° | +135° |

## 5. Example

MOVE with sequence number 42 to j1 = 12.5°, j2 = −30°, j3 = 45° at 120 deg/s, 22 bytes:

```
0000  41 4d 01 01 00 2a 00 0e  00 00 30 d4 ff ff 8a d0   AM...*....0.....
0010  00 00 af c8 00 78                                  .....x
```

| Bytes | Field | Value |
|---|---|---|
| `41 4d` | magic | "AM" |
| `01` | version | 1 |
| `01` | type | MOVE |
| `00 2a` | seq | 42 |
| `00 0e` | length | 14 |
| `00 00 30 d4` | j1 | 12500 m° = 12.5° |
| `ff ff 8a d0` | j2 | −30000 m° = −30° |
| `00 00 af c8` | j3 | 45000 m° = 45° |
| `00 78` | speed | 120 deg/s |

The controller's ACK, 12 bytes: status ok, the arm is on its way (queue 1), processed in 7 µs:

```
0000  41 4d 01 81 00 2a 00 04  00 01 00 07               AM...*......
```

A MOVE to j2 = 95° instead is refused with NACK 5:

```
0000  41 4d 01 82 00 2a 00 1e  05 6a 32 20 74 61 72 67   AM...*...j2 targ
0010  65 74 20 39 35 c2 b0 20  6f 75 74 73 69 64 65 20   et 95.. outside
0020  c2 b1 39 30 c2 b0                                  ..90..
```
