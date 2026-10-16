# Architecture

## Layout

```text
src/
  RdpClient.Protocol/    Protocol core — no UI dependency, plain .NET
  RdpClient.App/         WinUI 3 front end — Windows only
  RdpClient.Cli/         rdpprobe: console handshake harness
tests/
  RdpClient.Protocol.Tests/
docs/
```

## Why the core is a separate assembly

`RdpClient.Protocol` has no reference to WinUI, Windows App SDK, or any UI
type. It targets plain `net10.0`. That boundary exists for one reason: **WinUI 3
only exists on Windows**, so a UI-coupled protocol layer could never be reused
by another front end. Keeping the codec and PDU encoders UI-free means a
cross-platform client is a matter of writing a different shell, not rewriting
the protocol.

The WinUI project references the core through an ordinary `ProjectReference`.
Nothing in the core knows the reference exists.

## Module responsibilities

### `ByteCodec.cs`

`ByteWriter` and `ByteReader`. Everything in the project that touches bytes goes
through these two types, because RDP mixes several integer encodings and a
field written at the wrong width shifts everything after it.

The one non-obvious rule: **TPKT lengths are big-endian, everything else is
little-endian.** `U16BigEndian` exists solely for that field.

MCS integers are plain fixed-width values with no T.125 selector bits, so
`McsVariableByte` writes the narrowest representation and the reader takes an
explicit width. An earlier version implemented PerEncoding selectors; that was
wrong for RDP and was removed.

### `Rdp.cs`

Constants transcribed from MS-RDPBCGR, grouped by section with the section
number in a comment. Keeping them in one file makes them auditable against the
published tables without reading encoder code.

### `Negotiation.cs`

TPKT framing, the X.224 class 0 request/confirm envelopes, and the
`RDP_NEG_REQ` / `RDP_NEG_RSP` exchange. `Tpkt` and `X224ConnectionRequest` are
the only places that build TPKT, so the endianness rule has exactly one home.

The connection-confirm parser deliberately skips a fixed five bytes after the
X.224 code rather than trusting the length indicator, because RDP servers send
`0x0E` regardless of what follows.

### `Mcs.cs`

Connect Initial/Response, the GCC Conference Create Request, and the
domain-attach / user-attach / channel-join PDUs.

### `ClientPdu.cs`

`TS_UD_CS_CORE`, `SECURITY`, `NET`, `CLUSTER` and `USER`. `NET`, `CLUSTER` and
`USER` share a 6-byte TLV header; `CORE` has none and carries two fixed-width
NUL-padded fields.

### `RdpConnection.cs`

Sequences the exchange over TCP and reports progress through `OnEvent`.

Events fire on the socket's continuation thread. `MainPageViewModel` captures
the UI `DispatcherQueue` and marshals before touching observable state.

`RdpConnectionOptions.UseCorrelationId` and `LogTx` exist because the framing
defects were only diagnosable with a byte dump, and the fixes needed to be
reproducible.

## Design decisions worth knowing

**Stop at a protocol boundary rather than guess.** When the server selects
CredSSP, `ConnectAsync` returns `Failed` with an explanation. Sending an MCS
Connect Initial anyway would be a protocol violation, and the resulting reset
would look like a bug rather than a missing feature.

**Credentials never touch the log.** `rdpprobe` reads the password from
`RDP_PASSWORD` and never echoes it. `.gitignore` excludes `*.rdp` and `.env`.

**The password is a `string`.** `TS_UD_CS_USER` needs the UTF-16 byte length
before the bytes, so the secret must exist as a string. A client that
implemented CredSSP would not hold it at all — the TLS channel would. This is
recorded as a known limitation in the README's security section.

## Testing

Wire-format tests are pinned to bytes captured from `mstsc.exe`. Each framing
defect found during development now has a test named after the rule it broke,
so a regression points straight at the specification section.

Tests assert structure and exact bytes, not behaviour against a live server, so
they run offline in under a second.

## Not implemented, by design

The capability exchange, security negotiation, graphics pipeline and input
stack are absent. Each is a substantial subsystem: the graphics pipeline alone
needs a virtual desktop, bitmap codecs, and an RDP 6.x decompressor. Stopping
at the handshake boundary is more useful than a half-built renderer, and the
stopping point is reported accurately rather than hidden.