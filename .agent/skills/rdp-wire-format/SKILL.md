---
name: rdp-wire-format
description: >-
  Work on the RDP wire format in this repository: encode or decode a PDU, debug a
  connection that resets, verify bytes against a real client, or read a Windows
  security provider with the decompiler. Use when a change touches
  RdpClient.Protocol, when a host resets or closes the connection, when a TLS or
  SPNEGO error appears, or when a field's width or byte order is in question.
---

# RDP wire format work

## Building

Publish per runtime, never per solution platform:

```powershell
dotnet test                                       # 104 tests, must be green first
dotnet publish src/RdpClient.Cli\RdpClient.Cli.csproj -c Release -r win-x64 --self-contained true -o artifacts\rdpprobe\win-x64
dotnet publish src\RdpClient\RdpClient.csproj       -c Release -r win-x64 --self-contained true -o artifacts\app\win-x64
```

Two traps: `RdpClient.slnx` declares no platform configurations, so
`-p:Platform=x64` fails with `MSB4126`; and the WinUI app sets
`RuntimeIdentifier` without `SelfContained` while Release enables
`PublishTrimmed`, so a plain `dotnet build RdpClient.slnx -c Release` fails
with `NETSDK1102`. `--self-contained` is required.

## The loop that works

Do not derive bytes from memory and do not trust a spec example that does not
show the field. **Capture a real client and assert against it.**

1. Put a logging proxy in front of a live RDP host:

   ```powershell
   node tools/rdp-tap.mjs 3390 3389 tap.log
   & "$env:SystemRoot\System32\mstsc.exe" /v:localhost:3390
   ```

2. Change the encoder.
3. Run `rdpprobe --host localhost --port 3389 --hex` and diff its `TX` bytes
   against the capture.
4. Pin the result in `tests/RdpClient.Protocol.Tests/ProtocolTests.cs`.

That loop found every framing defect in this project. Guessing from the
specification did not find any of them.

## Reading a reset

| Symptom | Meaning |
| --- | --- |
| No reply, immediate close | The host rejected the PDU outright |
| `The decryption operation failed` | **Not a TLS problem.** Schannel reports a peer that vanished; the host closed |
| `RDP_NEG_RSP failure, code 5` | `SSL_REQUIRED_BY_SERVER`; the host mandates CredSSP |
| No answer to an unsolicited read | Normal: RDP clients speak first |

The host usually gives no diagnostic at all. That means the answer is in the
bytes, not in an error message.

## Invariants

Violating any of these causes an immediate reset, or a silent
desynchronisation that looks like a server bug.

- **TPKT length is big-endian.** The only big-endian field in the sequence.
- **X.224 order: length indicator, then TPDU code.** TPKT puts its length last.
- **Never trust `li` to locate a following structure.** Hosts send `0x0E`
  regardless of content; skip the fixed header (code, 2-byte dst, 2-byte src,
  class option) instead.
- **`TS_UD_CS_*` discriminators are 16-bit**, `03 C0` on the wire for `0xC003`.
- **The `TS_UD_HEADER` is 4 bytes: type(2), length(2). There is no flags
  field.** Every client data block has one, `TS_UD_CS_CORE` included. `CORE`
  is not the exception it looks like in older notes.
- **A `TS_UD_HEADER.length` covers the whole block, header included**, and is a
  plain little-endian count with **no** `0x8000` PER marker. Patch it in after
  the payload is written. `NET` is `12 * channelCount + 8`, because
  `CHANNEL_DEF` is a fixed 12 octets with no length prefix of its own.
- **Every MCS domain PDU is TPKT + X.224 Data TPDU + one opcode octet.** Erect
  Domain, Attach User and Channel Join all travel in that envelope. Sending
  them bare gets no diagnostic at all.
- **The opcode octet is not the PDU code.** It is the T.125 DomainMCSPDU
  CHOICE index in the top six bits with two option bits below:
  `opcode = (choice << 2) | options`. Erect Domain is `0x04`, not `0x05`.
- **The MCS global channel is 1003**, not 1007. 1007 is the H.225.0 RTP channel
  number.
- **The Channel Join initiator is the user id from the Attach User Confirm**,
  written as a PER integer relative to 1001. Not a hard-coded 1001.
- **The GCC conference name is a PER numeric string**, digits only. `McsCnxn`
  is the H.221 node label and cannot be encoded as one at all.
- **MCS integers are plain fixed-width values** with no T.125 selector bits,
  except where a field is a PER INTEGER, which carries its own length
  determinant: a zero is `01 00`, not a bare `00`.

## Read the reply before calling a stage done

The single most expensive defect class in this project. An earlier version
sent the Erect Domain, Attach User and Channel Join requests, read **none** of
the replies, and returned `Complete` - so `rdpprobe` printed

```text
RESULT: MCS channel joined.
```

against a server that had rejected the very first PDU:

```text
[ERROR] Parsing [MS-RDPBCGR] GCC Conference Create Request client data field
        Not enough bytes in the stream: expected 32764, remaining 308
[ERROR] Processing [ITU-T T.125] ErectDomainRequest failed
```

A client that cannot distinguish a refused connection from an accepted one
cannot be diagnosed at all. Every stage waits for the PDU that proves it.

Note that `TS_UD_CS_USER` does not exist in MS-RDPBCGR; xrdp answers
`TS_UD_HEADER type 0xc00e is unknown (ignored)`. Sending it by default
transmitted a cleartext password the server was about to discard.

## Using the decompiler

When a token or PDU is rejected, read the reference implementation rather than
inferring it. REA drives Ghidra and is configured for this machine:

```powershell
rea doctor --provider ghidra --json
rea search <path> --provider ghidra --kind strings --mode regex --pattern "<re>"
```

Open a binary **once** through the MCP server and issue many queries against the
session. Every `open_binary` costs a full auto-analysis of 5 to 10 minutes, so a
CLI call per question is wasteful.

Pick the binary that actually contains the code:

| Question | Binary |
| --- | --- |
| RDP client behaviour, COM surface | `mstsc.exe` (shell), `mstscax.dll` (logic) |
| NTLM message construction, flags, offsets | **`msv1_0.dll`** |
| Kerberos, NegoEx | `secur32.dll` — contains no NTLM at all |

`secur32.dll` returning zero NTLM hits is correct, not a broken search. Confirm
before concluding a binary is the right target.

## Scope

Encoding is verified against a live host through TLS. NTLM is not yet accepted
by the host, so no token layout in this repository is confirmed end to end. When
working on it, read `msv1_0.dll` rather than proposing another guess; seven
hypotheses have already been eliminated and the remaining one is unknown.

## Hygiene

- `rdpprobe` reads the password from `RDP_PASSWORD`; never print it.
- Intercepting TLS requires a certificate in a trust store. Remove every
  certificate afterwards and note what was touched.
- Report a failure with its cause. A partial success presented as complete is
  worse than a stated failure.