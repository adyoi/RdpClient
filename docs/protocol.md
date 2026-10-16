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

Appending the optional correlation block makes the PDU 55 bytes and **requires**
raising `CORRELATION_INFO_PRESENT`.

### Correlation block (2.2.1.1.2)

| Field | Size | Value |
| --- | --- | --- |
| `type` | 1 | `0x06` `TYPE_RDP_CORRELATION_INFO` |
| `flags` | 1 | `0x00` |
| `length` | 2 | `0x0024` — **36**, larger than the fields it names |
| `correlationInfo` | 16 | client-chosen vector |
| `type` | 2 | `0x0001` `RPC_CORRELATION_VECTOR_INFO1` |
| `Reserved` | 2 | `0x0000` |

The named fields add up to 24 octets, but the structure declares 36, so the
sent bytes must be padded to cover the length the client writes itself.
Sending only the 24 named fields was accepted by Windows and rejected by xrdp,
which walks `1 + 2 + 16 + 16` octets after the type and aborts the connection:

```text
Parsing [MS-RDPBCGR] RDP_NEG_CORRELATION_INFO Not enough bytes in the stream:
expected 35, remaining 23
```

With the padding, xrdp answers with a Connection Confirm and selects
`PROTOCOL_SSL` instead of dropping the connection.

Note that `mstsc.exe` never sends this block at all — a capture of it through
`tools/rdp-tap.mjs` shows the 19-byte request — and neither does FreeRDP, so a
Windows host does not exercise the encoding either way.

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

Carried in the same X.224 envelope as the negotiation request, but the payload
is **ASN.1, not a flat TLV**. It is the T.125 structure:

```text
Connect-Initial ::= [APPLICATION 101] IMPLICIT SEQUENCE
{
    callingDomainSelector   OCTET STRING  -- 0x01
    calledDomainSelector    OCTET STRING  -- 0x01
    upwardFlag              BOOLEAN       -- TRUE, the client is joining
    targetParameters        DomainParameters
    minimumParameters       DomainParameters
    maximumParameters       DomainParameters
    userData                OCTET STRING  -- the GCC Conference Create Request
}
```

DomainParameters is a SEQUENCE of eight INTEGERs: `maxChannelIds`,
`maxUserIds`, `maxTokenIds`, `numPriorities`, `minThroughput`, `maxHeight`,
`maxMCSPDUsize`, `protocolVersion`.

### The tag is split

101 does not fit the five tag bits of one octet, so it is written as all-ones
followed by the number: **`7f 65`**. A server that rejects the structure names
the identifier it wanted, which is what identified this defect rather than
leaving it to guesswork:

```text
[ERROR] Parsed [ITU-T X.690] Identifier: expected 0x7f65, actual 0x0300
```

`0x0300` was the TLV this client used to write: tag `0x03`, length `0x00`.

### Connect Response is the mirror image

`[APPLICATION 102]`, so `7f 66`, wrapping `result ENUMERATED`,
`calledConnectId INTEGER`, `domainParameters` and `userData`.

### The user data is PER-encoded

The GCC Conference Create Request inside `userData` is T.125's ALIGNED variant
of BASIC-PER, which is neither BER nor a plain TLV:

```text
00                          From Key: the OBJECT_IDENTIFIER alternative
05 00 14 7C 00 01           T.124 (02/98) object identifier, six octets
<PER length>                connectPDU length - client data + 14
00                          ConnectGCCPDU: conferenceCreateRequest
08                          selection: userData present
<PER numeric string>        the conference name, digits only
00 01                       one set of user data
C0                          value present, h221NonStandard selected
00 "Duca"                   the client-to-server H.221 key
<PER length> <client data>  the TS_UD_CS_* blocks
```

Two details in that differ from everything else in RDP:

- **The conference name is a numeric string.** Digits pack a pair to an octet,
  `(d1 << 4) | d2`, with an implied trailing `0` on an odd length, so the name
  `"1"` is the single octet **`0x10`**, not `0x01`. `McsCnxn` is not a conference
  name at all: it is the H.221 node label from the older T.125 CCPDU, and
  encoding it as a numeric string fails at the first non-digit.
- **PER lengths are not BER lengths.** Under 128 the length is one octet; above
  it the high bit is set and the whole two-octet value is kept big-endian,
  rather than the high bit counting the octets that follow the way it does in
  BER. `WritePerLength` and `BerLength` therefore disagree on purpose.

The response side mirrors it, and carries one more trap: the `connectPDU`
length in a Conference Create Response **must be ignored**. Servers do not agree
on what it counts, so a client that trusts it desynchronises.

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