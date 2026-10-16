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
dotnet test                                       # 69 tests, must be green first
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

Violating any of these causes an immediate reset.

- **TPKT length is big-endian.** The only big-endian field in the sequence.
- **X.224 order: length indicator, then TPDU code.** TPKT puts its length last.
- **Never trust `li` to locate a following structure.** Hosts send `0x0E`
  regardless of content; skip the fixed header (code, 2-byte dst, 2-byte src,
  class option) instead.
- **`TS_UD_CS_*` discriminators are 16-bit**, `03 C0` on the wire for `0xC003`.
- **`NET` / `CLUSTER` / `USER` have a 6-byte TLV header**: type(2), flags(2),
  length(2). `CORE` has none and carries two fixed-width NUL-padded fields.
- **The GCC conference name length is in UTF-16 code units.** `McsCnxn` is 7
  characters, 14 bytes.
- **MCS integers are plain fixed-width values** with no T.125 selector bits.

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