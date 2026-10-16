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
dotnet build                 # whole solution
dotnet test                  # protocol tests, must be green before committing
dotnet build -p:Platform=x64 # also ARM64 and x86
winapp run                   # launch the WinUI app from src/RdpClient
```

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
| MCS Connect Initial / Response | 2.2.1.3.4, 2.2.1.3.5 | Written, unreachable |
| RSA key exchange, session keys, MCS encryption | 5.3.2 | Not started |
| Capability exchange | 2.2.7 | Not started |
| Graphics and input | 2.2.8, 2.2.9 | Not started |

Do not describe this as a working remote desktop client. It reaches TLS and
authenticates nothing.

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
4. **`NET`, `CLUSTER` and `USER` carry a 6-byte TLV header**: type(2),
   flags(2), length(2). `CORE` has no TLV header and two fixed-width
   NUL-padded fields.
5. **The GCC conference name length counts UTF-16 code units, not bytes.**
   `McsCnxn` is 7 characters and 14 bytes.
6. **MCS integers are plain fixed-width values.** There are no T.125
   PerEncoding selector bits in RDP; a width-aware writer and reader are used
   instead.

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
| Large binaries | `REA_GHIDRA_STARTUP_TIMEOUT_MS=1800000` |

Those are written into `.config/opencode/opencode.json`; keep them there when
regenerating client configuration.

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