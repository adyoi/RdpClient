# Protocol notes

Field-by-field notes for every PDU this project emits, with the governing
section of **MS-RDPBCGR** ([MS-RDPBCGR][spec]). Values are transcribed from the
specification rather than from captured traffic, so each can be checked against
the published tables.

[spec]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/

## Byte order

RDP is little-endian with exactly one exception:

| Region | Endianness |
| --- | --- |
| TPKT header length (RFC 1006) | **Big-endian** |
| Everything inside TPKT | Little-endian |

Getting the TPKT length wrong looks like an instant connection reset, because
[MS-RDPBCGR 3.3.5.3.1][proc] requires the server to verify that the embedded
length fields agree with the received data and drop the connection when they do
not.

[proc]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/674600ba-15ca-4276-83ca-7bd48a9c2944

## 1. X.224 Connection Request (2.2.1.1)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (3)  |  Reserved (0) |         Length (BE)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Length ind.  |   Code (0xE0) |     Destination reference     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Source reference          | Class (0)  |    RDP_NEG_REQ     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          RequestedProtocols (4) ...        | (optional) rdpCorr|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Two ordering rules are easy to get backwards:

- **TPKT** puts the length **last** (version, reserved, length).
- **X.224** puts the length indicator **first** (indicator, then TPDU code).

The server sends `Length indicator = 0x0E` regardless of what follows it, so a
client must not use it to locate the `RDP_NEG_RSP`. Skip the fixed header:
after the code, destination reference (2), source reference (2) and class (1).

A minimal request is exactly 19 bytes:

```text
03 00 00 13 | 0e e0 00 00 00 00 00 | 01 00 08 00 | 0b 00 00 00
^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^  ^^^^^^^^^^^^
TPKT        X.224 class 0        RDP_NEG_REQ    PROTOCOL_SSL |
                                               HYBRID       |
                                               HYBRID_EX
```

`0x0B` is what `mstsc.exe` advertises; a client offering only `0x03` is
narrower but still interoperable.

## 2. RDP Negotiation Request (2.2.1.1.1)

| Field | Size | Value |
| --- | --- | --- |
| `type` | 1 | `0x01` |
| `flags` | 1 | `CORRELATION_INFO_PRESENT` (`0x08`) when the correlation block follows |
| `length` | 2 | `0x0008` |
| `requestedProtocols` | 4 | Protocol bitmask |

Appending the optional correlation block makes the PDU 43 bytes and **requires**
raising `CORRELATION_INFO_PRESENT`.

### SelectedProtocol

| Bit | Protocol | Meaning |
| --- | --- | --- |
| `0x01` | `PROTOCOL_SSL` | TLS only, then MCS |
| `0x02` | `PROTOCOL_HYBRID` | CredSSP |
| `0x04` | `PROTOCOL_RDSTLS` | Reserved for RDSTLS |
| `0x08` | `PROTOCOL_HYBRID_EX` | CredSSP, extended |
| `0x10` | `PROTOCOL_RDSAAD` | CredSSP, Azure AD |

Anything other than `PROTOCOL_SSL` means a CredSSP handshake runs before MCS.
A client that does not implement CredSSP must stop here rather than send an MCS
Connect Initial, which the server would treat as a protocol violation. That is
what this project does.

## 3. MCS Connect Initial (2.2.1.3.4)

Carried in the same X.224 envelope as the negotiation request.

```text
ProtocolVersion (1) = 0x03
RSTransactionId (2)
Cookie (2)         = 0xA0A0
ConnectData (variable, 2-byte length prefix)
    t124 Identifier (1) = 0x01
    ConferenceName       2-byte length in UTF-16 code units, then UTF-16LE
    Label (2)            = 0x0001
ClientNodeId (variable, 2-byte length prefix)
ClientInfo (variable, 2-byte length prefix)
    TS_UD_CS_* blocks
```

The conference name length counts **characters**, not bytes. `McsCnxn` is seven
characters and therefore fourteen bytes; encoding that as `6` is a common and
silently fatal mistake.

## 4. Client data blocks (2.2.1.3.4.1–.5)

`TS_UD_CS_NET`, `TS_UD_CS_CLUSTER` and `TS_UD_CS_USER` share a 6-byte TLV
header:

```text
type (2) | flags (2) | length (2) | payload
```

The discriminator is 16-bit. `TS_UD_CS_NET` is `0xC003`, which appears on the
wire as `03 C0`; writing it as a single byte leaves it as `03` and shifts every
following field by one.

`TS_UD_CS_CORE` has no TLV header. Two of its fields are fixed-width and are
NUL-padded rather than length-prefixed:

| Field | Size |
| --- | --- |
| `ClientName` | 32 bytes (16 UTF-16 units) |
| `imeFileName` | 64 bytes (32 UTF-16 units) |

`TS_UD_CS_USER` field lengths are **byte** counts, so a 5-character user name
is declared as 10.

## 5. MCS channel setup (2.2.1.3.6–.8)

After Connect Response the client erects the server domain, attaches itself as
a user, and joins the MCS global channel (1007). Payload framing for later data
uses MCS Send Data Request, chunked at 1598 bytes.

## Reference implementation

The encoders are pinned by unit tests to bytes recorded from `mstsc.exe` through
a logging TCP proxy. See `tests/RdpClient.Protocol.Tests/ProtocolTests.cs`.