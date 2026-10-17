# AGENTS.md

Instructions for coding agents working in this repository.

## What this is

An RDP client for Windows, written from Microsoft's public Open Specifications
([MS-RDPBCGR][spec], [MS-RDPEA][spea], [MS-NLMP][nlmp]) rather than from source
code or by disassembling `mstsc.exe`.

[spec]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
[spea]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpea/
[nlmp]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/

## Build and test

```powershell
dotnet build                                      # whole solution, Debug
dotnet test                                       # protocol tests, must be green
winapp run                                        # launch the WinUI app from src/RdpClient
```

Shipping binaries. **Publish per runtime, not per solution platform**:
`RdpClient.slnx` declares no platform configurations, so `-p:Platform=x64`
fails with `MSB4126`.

```powershell
dotnet publish src/RdpClient.Cli\RdpClient.Cli.csproj -c Release -r win-x64 --self-contained true -o artifacts\rdpprobe\win-x64
dotnet publish src\RdpClient\RdpClient.csproj       -c Release -r win-x64 --self-contained true -o artifacts\app\win-x64
```

`--self-contained` is **required** for the WinUI app. It sets `RuntimeIdentifier`
without `SelfContained`, and Release enables `PublishTrimmed`, so a plain
`dotnet build RdpClient.slnx -c Release` fails with `NETSDK1102`. Use
`win-x64`, `win-arm64` or `win-x86`.

`RdpClient.Protocol` compiles with `TreatWarningsAsErrors`. Fix warnings rather
than widening `NoWarn`. `CS1591` is already suppressed because the XML doc file
exists for IntelliSense; everything non-obvious is documented at the member.

## Current state, honestly

| Layer | Spec | State |
| --- | --- | --- |
| X.224 / T.125 connection request | 2.2.1.1 | Verified against a live host |
| RDP negotiation | 2.2.1.1.1, 2.2.1.2.1 | Verified |
| TLS handshake | MS-RDPEA 3.1.5.1 | Verified, TLS 1.2 and 1.3 |
| CredSSP `TSRequest` envelope | MS-CSSP 2.2.1 | **Encoded and verified structurally**; host now parses it |
| SPNEGO + NTLM | MS-NLMP | **Not working**, host returns `SEC_E_INVALID_TOKEN` |
| MCS Connect Initial / Response | 2.2.1.3.4, 2.2.1.3.5 | **Verified against xrdp** |
| GCC client data (`TS_UD_CS_*`) | 2.2.1.3 | **Verified against xrdp**; the blocks are accepted |
| Erect Domain / Attach User / Channel Join | 2.2.1.5, 2.2.1.6, 2.2.1.8 | **Verified against xrdp**, and the Confirms are read |
| RSA key exchange, session keys, MCS encryption | 5.3.2 | Not started |
| Capability exchange | 2.2.7 | Not started |
| Graphics and input | 2.2.8, 2.2.9 | Not started |

Do not describe this as a working remote desktop client. It reaches TLS and
authenticates nothing. Against xrdp it completes the MCS channel join, which is
the honest stopping point: the next PDU is the Demand Active, and that starts
the capability exchange.

## The client must read the server's answer

**A stage is not complete until the reply has been read and parsed.** The
original code sent the Erect Domain, Attach User and Channel Join requests and
then reported `Complete` without reading a single reply, so a server that had
rejected the first PDU was still reported as a completed channel join. That is
the most expensive class of defect in this repository: it makes a broken
connection look like a working one.

`AttachUserConfirm` is not optional bookkeeping. It is the **only** place the
server states which user id it assigned, and the Channel Join Request must
carry that id. A conventional 1001 is not a substitute.

xrdp reports the same failure from the other side, so the two have to be read
together:

```text
client: joined MCS channel 1003
xrdp:   [ERROR] Processing [ITU-T T.25] ChannelJoinRequest failed
        [ERROR] libxrdp_force_read: header read error
```

## Reading the channel join

`expecting_channel_join_requests` is set after the Attach User Confirm in xrdp,
and its comment says "zero or more channel join requests are expected at this
point". A client that joins only the MCS global channel and then stops gets one
`ChannelJoinRequest` accepted and a second read that hits EOF. Seeing exactly
that pair - one accepted join, then a read error on the *next* join - means the
framing is right and the session simply ended early, which is what happens
before the capability exchange exists.

Windows refuses `PROTOCOL_SSL` alone with failure code 5,
`SSL_REQUIRED_BY_SERVER`, because it wants NLA. So the Windows host cannot
exercise the MCS stage at all until NTLM works - **xrdp is the only server that
can currently verify anything past TLS.** That is worth remembering before
concluding that a change is fine because Windows tolerates it.

## Ask the server what it thinks

Schannel reports a CredSSP rejection as a TLS error, which is useless:

> The decryption operation failed ... The Local Security Authority cannot be
> contacted

That message means the peer closed the socket. The real reason is in the server's
event log, and it names the exact failure:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" -MaxEvents 20 |
  Where-Object Id -in 139,226,102 | Sort-Object TimeCreated |
  ForEach-Object { "{0:HH:mm:ss.fff} id={1} {2}" -f $_.TimeCreated, $_.Id,
                   ($_.Message -replace "\s+"," ").Trim() }
```

Event 139 carries the NTSTATUS, for example
`The server security layer detected an error (0x80090308) in the protocol stream`.
`0x80090308` is `SEC_E_INVALID_TOKEN`, which in the `msv1_0.dll` validator is what
NTLM returns when a message fails its signature, type or size check.

Use this before forming a theory. It distinguishes "the peer never understood me"
from "the peer understood me and rejected one specific field", which look
identical from the client side.

## Wire-format invariants

Each of these produced an immediate connection reset when wrong. They are the
reason `docs/protocol.md` exists; read it before touching an encoder.

1. **The TPKT length is big-endian.** It is the only big-endian field in the
   connection sequence. Everything inside TPKT is little-endian.
2. **X.224 puts the length indicator before the TPDU code.** TPKT puts its
   length last. Servers send `li = 0x0E` regardless of content, so never use
   `li` to locate a following structure; skip the fixed header instead.
3. **`TS_UD_CS_*` discriminators are 16-bit.** `TS_UD_CS_NET` is `0xC003` and
   appears as `03 C0`. Writing it as one byte shifts every following field.
4. **The `TS_UD_HEADER` is 4 bytes: type(2), length(2). There is no flags
   field.** Every client data block starts with one, `TS_UD_CS_CORE` included.
   CORE is not the exception it was long taken to be; writing six octets where
   four belong shifts every payload field by two.
5. **A `TS_UD_HEADER.length` covers the whole block, header included.** It is a
   plain little-endian 16-bit count with **no** `0x8000` PER marker - that
   marker belongs to the PER lengths around the GCC data and to nothing else
   here. A reader walks the length to find the next block, so a block that
   declares less than it sends desynchronises everything after it. `NET` is
   `12 * channelCount + 8`, because CHANNEL_DEF is a fixed 12 octets with no
   length prefix of its own.
6. **A MCS domain PDU is TPKT + X.224 Data TPDU + one opcode octet**, in that
   order. Erect Domain, Attach User and Channel Join all travel in that
   envelope, and sending them bare produces no diagnostic at all.
7. **That opcode octet is not the PDU code.** It is the T.125 DomainMCSPDU
   CHOICE index in the top six bits with two option bits below:
   `opcode = (choice << 2) | options`. Erect Domain is choice 1, so the octet is
   `0x04`, not `0x05`. Reading the octet as the code lands on a different PDU.
8. **The MCS global channel is 1003**, not 1007. 1007 is the H.225.0 RTP channel
   number and has no business in an MCS channel list.
9. **The MCS Connect-Initial is ASN.1, not a flat TLV.** It is
   `Connect-Initial ::= [APPLICATION 101] IMPLICIT SEQUENCE` carrying two domain
   selectors, an upward flag, three sets of domain parameters and the user data.
   101 does not fit the five tag bits of one octet, so the identifier is
   **`7f 65`**. Writing it as a length-prefixed TLV gets `expected 0x7f65,
   actual 0x0300` out of xrdp - which is how the mistake was found.
10. **The conference name inside it is a PER numeric string, digits only.**
   Two digits pack to an octet, `(d1 << 4) | d2`, with an implied trailing `0`
   on an odd length, so the name `"1"` is the octet **`0x10`** and not `0x01`.
   `McsCnxn` is not a conference name: it is the H.221 node label from the older
   T.125 CCPDU, and it cannot be encoded as a numeric string at all.
11. **A PER length is not a BER length.** Under 128 it is one octet. Above it the
    high bit is set and the full two-octet value is kept big-endian, rather than
    the high bit counting the octets that follow the way BER does. In a
    Conference Create Response the `connectPDU` length must be **ignored
    entirely** - servers disagree on what it counts - but it still occupies one
    or two octets, so it has to be stepped over as a variable-width field
    rather than skipped as a single octet.
12. **Skip the TPKT header before parsing the X.224 envelope.** Reading at
   offset 0 of a TPKT datagram takes `0x03`, the TPKT version, as if it were the
   MCS result. That is the origin of a whole family of phantom
   "connection refused" reports. The X.224 Data TPDU is length indicator, DT
   code, EOT - so the DT code is the *second* octet.
13. **A CredSSP `TSRequest` field declared `[n] INTEGER` wraps a whole INTEGER
   TLV.** `version` is `a0 03 02 01 06`, not `a0 01 06`. The second declares one
   content byte holding a bare `0x06`, which is not a valid INTEGER, so the
   whole request stops being valid DER.
14. **An NTLM field descriptor is `{ Length(2), MaxLen(2), BufferOffset(4) }`.**
   The offset is 32-bit. Reading Length from `[4..6]` and Offset from `[6..8]`
   takes the two halves of the offset instead, which silently yields the offset
   as the length and zero as the offset.
15. **A structure must be as long as the length field it declares.** The NTLM
   `BufferOffset` above is 4 octets and had to be written as 4. Likewise
   `RDP_CORRELATION_INFO` declares 36 while its named fields occupy 24, so the
   block is padded. xrdp walks the declared length and aborts with
   `Not enough bytes in the stream: expected 35, remaining 23`; Windows ignores
   the discrepancy, so only a second implementation catches this class of
   defect.
16. **The GCC `connectPDU` length counts its own inputs, not a constant.** It is
    the client data, twelve octets of fixed framing, and the client-data length
    field - and that field is one octet while the client data is below 0x80. A
    flat 14 is right only above that. `mstscax.dll` writes
    `(0xe - (uint)(uVar3 < 0x80)) + uVar3`, which is `12 + width + clientData`.
    Note the corollary: a total that crosses 0x80 while the client data does not
    still takes two octets, so the two widths are not interchangeable.

## Section numbers, and a block that does not exist

Several references were wrong long enough to hide the defects above:

- The MCS connection PDUs are **2.2.1.5, 2.2.1.6 and 2.2.1.8**, not
  2.2.1.3.6-8, which are the client data blocks.
- `TS_UD_CS_CLUSTER` is **2.2.1.3.5**, not 2.2.1.3.4.4.
- **`TS_UD_CS_USER` does not exist in MS-RDPBCGR.** xrdp answers
  `TS_UD_HEADER type 0xc00e is unknown (ignored)`. It is a classic-RDP
  structure that predates the specification, it puts a password on the wire in
  UTF-16 in the clear, and it is opt-in here rather than sent by default.

## A second server is how encoding bugs get caught

Windows tolerates more than the specification forbids, and both `mstsc.exe` and
FreeRDP skip the optional structures entirely, so testing against Windows alone
cannot settle whether an encoding is right. xrdp is strict about declared
lengths and names the structure it was parsing in its log, which is what turned
the correlation block from a guess into a measurement:

```bash
wsl -d Ubuntu-26.04 -- tail -40 /var/log/xrdp.log
```

Read that log before forming a theory, exactly as the Windows event log is read
above. [docs/wsl-rdp-lab.md](docs/wsl-rdp-lab.md) is the full setup, including
the desktop choices and the idle-shutdown trap.

## Verifying a wire-format change

The single most useful thing in this project. Do not reason about bytes from
memory, and do not rely on a spec example that does not cover the field.

Capture a real client:

```powershell
# logging TCP proxy in front of a local RDP host
node tools/rdp-tap.mjs 3390 3389 tap.log
& "$env:SystemRoot\System32\mstsc.exe" /v:localhost:3390
```

Then assert the produced bytes against the capture in
`tests/RdpClient.Protocol.Tests/ProtocolTests.cs`. `ConnectionRequest_MatchesBytesCapturedFromMstsc`
is the reference test.

When a PDU is malformed the host usually resets with no diagnostic, and Schannel
reports the reset as "The decryption operation failed". That message means
nothing about TLS; it means the peer went away.

## Reverse engineering tooling (REA)

REA provides a Ghidra-backed MCP server. Setup on this machine:

| | |
| --- | --- |
| `GHIDRA_INSTALL_DIR` | `C:\tools\ghidra_12.1.4_PUBLIC` |
| `JAVA_HOME` | `C:\tools\jdk-21.0.12.1+1` |
| `GHIDRA_HEADLESS_MAXMEM` | `8G` |
| Large binaries | `REA_GHIDRA_STARTUP_TIMEOUT_MS=1800000` |

Those are written into `.config/opencode/opencode.json`; keep them there when
regenerating client configuration.

**`GHIDRA_HEADLESS_MAXMEM` is not optional.** `support/analyzeHeadless.bat`
hardcodes `MAXMEM_DEFAULT=2G`, and Ghidra exits with code 1 partway through
auto-analysis of `mstscax.dll` on that heap - the MCP call surfaces it as
`execution_failure` with an `exit_code: 1` diagnostic, not as an out-of-memory
error, so it reads like a broken analysis rather than a missing setting. The box
had 8.9 GB free when it happened. Raising the default to 8G makes the same
analysis complete in about ten minutes.

**A string search will not find the H.221 key.** `Duca` is absent from every
Ghidra-defined string Data item, so `search_strings` returns nothing and that
looks like evidence of absence. It is an immediate embedded in the instruction
stream, at `0x180163808` inside `FUN_180163600`, which is the GCC Conference
Create Request builder. Search for the bytes in hex - `44 75 63 61` - rather
than as text. `search_bytes` takes hex only and rejects a literal.

```powershell
rea doctor --provider ghidra --json
rea analyze <path> --provider ghidra --json
rea search <path> --provider ghidra --kind strings --mode regex --pattern "<re>"
```

**Use one MCP session for many queries.** Each `open_binary` costs a full Ghidra
auto-analysis, which runs 5 to 10 minutes on a binary of any size. Opening once
and issuing many `search_strings` / `procedure_pseudo_code` calls is far cheaper
than one CLI invocation per question.

Which binary to open matters. Windows splits the RDP stack:

| Component | Binary |
| --- | --- |
| RDP client shell | `mstsc.exe` (1.1 MB, no dialogs; a thin host) |
| RDP client logic, ActiveX control | `mstscax.dll` (8.7 MB, 22,685 functions) |
| **CredSSP / TSRequest envelope** | **`credssp.dll` (53 KB, "Microsoft CredSSP Security Provider")** |
| **NTLM implementation** | `msv1_0.dll` (608 KB) |
| Kerberos / NegoEx | `secur32.dll` (53 KB, contains no NTLM) |

`credssp.dll` is the binary that matters for CredSSP. Its exports are the
`Sp*` set (`SpInitializeSecurityContextW` and so on) and its string table
contains `Negotiate`, which is the SSPI package it negotiates *through* - so the
token in `negoToken` is SPNEGO, not a bare NTLM message.

`SpInitializeSecurityContextW` copies the underlying package's output buffer
straight into the serializer, and `FUN_180003cd8` in that DLL is the routine
that assembles the final `TSRequest`.

## When authentication fails, reach for the decompiler

Do not guess a token layout. The reference implementations are on disk and
Ghidra will read them:

- `msv1_0.dll` holds the NTLMSSP message construction, including the
  NEGOTIATE flag set and field offsets.
- The SPNEGO wrapper is BER; the correct `NegTokenInit` shape can be read from
  the same binary or from `secur32.dll`'s NegoEx path.

Seven hypotheses about the SPNEGO token were tested and eliminated in this
repository's history. The eighth turned out to be a missing layer rather than a
malformed one: **the client was sending a bare SPNEGO token with no CredSSP
`TSRequest` envelope at all.** That is fixed and pinned by `CredSspTests`.

The host now reports `0x80090308` instead of resetting silently, which means it
parses the envelope and rejects the token *inside* it. Both a bare NTLM message
and the SPNEGO-wrapped one produce the same status, so the remaining defect is
inside the SPNEGO or NTLM content, not the envelope.

### Settled: the NTLM flag values are correct

This looked wrong and was checked. It is not. MS-NLMP 2.2.2.5 labels the 32 bits
of `NegotiateFlags`, which fixes every value:

```
bit: 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0
lbl:  W  V  U r1 r2 r3  T  r4  S  R r5  Q  P r6  O  N  M r7  L  K  J r8  H r9  G  F  E  D r10 C  B  A
```

`W` is 56-bit encryption (bit 31), `V` key exchange (30), `U` 128-bit (29),
`T` version (25), `S` target info (23), `R` non-NT session key (22),
`Q` identify (20), `P` extended session security (19), `M` always sign (15),
`L` OEM workstation supplied (13), `K` OEM domain supplied (12), `J` anonymous
(11), `H` **NTLM** (9), `G` LM key (7), `F` datagram (6), `E` seal (5),
`D` sign (4), `C` request target (2), `B` OEM (1), `A` Unicode (0).

So `NegotiateNtlm = 0x00000200` is right, and so are
`NegotiateOemWorkstationSupplied = 0x00002000` and
`NegotiateOemDomainSupplied = 0x00001000`. `Ntlm.ClientFlags` encodes to
`0xE2088207`, which matches the bytes on the wire.

**Do not change these values.** They were suspected once and the suspicion was
wrong. The NTLM NEGOTIATE is not the reason the host rejects the token.

## Conventions

- Transcribe constants from the specification with the section number in a
  comment; do not copy values from another implementation.
- Comments should explain *why* a field is the size it is, especially where the
  obvious choice is wrong.
- Never log or commit credentials. `rdpprobe` reads the password from
  `RDP_PASSWORD` and must never echo it.
- When something does not work, say so and say why. This project reports a
  failure with its cause rather than claiming partial success.

## Security

Installing a certificate into a trust store to intercept a TLS session changes
the machine's security posture. If you do it, remove every certificate
afterwards and record what was touched in the changelog.