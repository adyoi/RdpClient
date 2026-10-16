<div align="center">

<img src="docs/assets/logo-256.png" alt="RdpClient logo" width="128" />

# RdpClient

**An RDP client built from Microsoft's public Open Specifications.**

[![Windows](https://img.shields.io/badge/platform-Windows-0078D4?logo=windows&logoColor=white)](https://learn.microsoft.com/windows/apps/winui/)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[Documentation](https://adyoi.github.io/RdpClient/) · [Releases](https://github.com/adyoi/RdpClient/releases) · [Issues](https://github.com/adyoi/RdpClient/issues)

</div>

---

## What this is

`RdpClient` is a native Windows remote-desktop client implemented **from the specification**, not
from source code. The RDP protocol is documented publicly by Microsoft as
[MS-RDPBCGR](https://learn.microsoft.com/openspecs/windows_protocols/ms-rdpbcgr/17a977be-ba6e-4624-9a1c-49a4d8313ac2)
and its companion documents, so the client can be written and audited without disassembling
anything.

The goal is a client you control and can read, for interoperability with Windows RDP hosts and
for understanding the protocol itself.

> **Status: connection sequence only.** See [Scope](#scope-what-works-and-what-does-not) below
> for exactly what is implemented. Security negotiation, graphics and input are **not**
> implemented, so the app does not display a remote desktop yet.

![RdpClient main window](docs/assets/screenshot-main.png)

## Why from the specification

Windows ships `mstsc.exe` and `mstscax.dll`, but neither is documented and both change
every Windows release. Analysis of the shipping client confirms how much is actually involved:

| Measurement | Value | Source |
| --- | ---: | --- |
| `mstscax.dll` size | 8.7 MB | SHA-256 `2fa54a09…` |
| Functions | **22,685** | Ghidra 12.1.4 decompilation |
| Defined strings | **20,552** | Ghidra 12.1.4 decompilation |
| COM interfaces exposed | `IMsRdpClient` 2–9, `IMsRdpClientAdvancedSettings` 2–8, `IMsRdpClientNonScriptable` 2–8 | embedded type library |

Reading the type library alone yields a usable blueprint: `Connect`, `ConnectWithEndpoint`,
`ConnectToAdministerServer`, `ExtendedDisconnectReason`, `RdpFileContents`, `PortablePassword`,
`RdpdrClip*`. Those are the seams a reimplementation needs, and they are all documented too.

See [docs/research.md](docs/research.md) for the analysis and its limitations.

## Scope: what works and what does not

Honesty here matters more than a feature checklist. The connection sequence is implemented and
verified against a live server. Everything after channel join is not.

| Layer | Spec | Status |
| --- | --- | --- |
| X.224 / T.125 connection request | — | **Done** |
| RDP Negotiation (`RDP_NEG_REQ` / `RDP_NEG_RSP`) | 2.2.1.1 | **Done** |
| MCS Connect Initial / Connect Response | 2.2.1.3.4, 2.2.1.3.5 | **Done** |
| GCC Conference Create Request / Response | 2.2.1.3.2, 2.2.1.3.3 | **Done** |
| `TS_UD_CS_CORE` / `SECURITY` / `NET` / `CLUSTER` / `USER` | 2.2.1.3.4.1–.5 | **Done** |
| Erect Domain, Attach User, Channel Join | 2.2.1.3.6–.8 | **Done** |
| RSA key exchange, RC4 / AES session keys | 2.2.1.4.3, 5.3.2 | Not started |
| CredSSP / NLA (TLS + SPNEGO + NTLM) | MS-RDPEA | Not started |
| Capability set exchange | 2.2.7 | Not started |
| Bitmap / pointer / order graphics pipeline | 2.2.9 | Not started |
| Keyboard and pointer input | 2.2.8 | Not started |
| Virtual channel data (clipboard, drive, audio) | 2.2.6 | Not started |

A modern host negotiates successfully and then selects CredSSP, so the client
stops there and says why. It does not send an MCS Connect Initial it knows the
server will reject.

## Platform support

**Windows only**, on x64, ARM64 and x86.

This is a hard platform limit, not a roadmap item: **WinUI 3 ships only for Windows**. There is
no macOS or Linux build of this app, and adding one would mean replacing the entire UI layer.

The protocol core (`RdpClient.Protocol`) is deliberately free of any UI dependency and targets
plain .NET, so it can be reused from a cross-platform front end if one is ever wanted. Only
`RdpClient.App` is Windows-bound.

| Architecture | Build | Notes |
| --- | --- | --- |
| `x64` | Supported | Windows 10 1809+ |
| `ARM64` | Supported | Native |
| `x86` | Supported | 32-bit; Windows on ARM runs it emulated |

## Requirements

- Windows 10 1809 (build 17763) or later
- [.NET SDK 10.0](https://dotnet.microsoft.com/download) to build
- [WinApp CLI](https://learn.microsoft.com/windows/apps/develop/cli/) (`winget install Microsoft.WinAppCLI`) to run

## Build and run

```powershell
git clone https://github.com/adyoi/RdpClient.git
cd RdpClient

dotnet build                                   # default platform
winapp run                                    # launch with package identity
```

Build a specific architecture:

```powershell
dotnet build -p:Platform=x64
dotnet build -p:Platform=ARM64
dotnet build -p:Platform=x86
```

### Probe the handshake from a terminal

The protocol core ships with a console harness, so the connection sequence can be exercised
without the GUI:

```powershell
dotnet run --project src/RdpClient.Cli -- --host 192.0.2.10 --port 3389
```

Actual output against a Windows host with NLA enabled:

```text
RdpClient protocol probe -> 127.0.0.1:3389
protocol core: RdpClient.Protocol 1.0.0.0

07:12:02.589  info    resolving 127.0.0.1...
07:12:02.612  info    connecting to 127.0.0.1:3389...
07:12:02.622  info    TCP established to 127.0.0.1:3389
07:12:02.624  info    sent X.224 Connection Request (43 bytes)
07:12:02.632  info    negotiated version 0x00000008, SelectedProtocol 0x00000008; correlation NOT echoed
07:12:02.632  error   server selected HYBRID_EX, which requires the CredSSP/NLA handshake
                      (TLS + SPNEGO + NTLM). That handshake is not implemented, so the
                      MCS layer cannot start.

RESULT: failed - server selected HYBRID_EX, ...
```

**That stop is the honest current state.** Negotiation completes and is verified
against a real host; the run then ends because a modern host selects CredSSP. Add
`--hex` to dump transmitted PDUs, or `--no-correlation` to send the minimal
19-byte request.

The harness never prints the password, and reads it from `RDP_PASSWORD` when one is needed.

## Project layout

```text
src/
  RdpClient.Protocol/   Protocol core. No UI dependency, plain .NET.
    ByteCodec.cs          Little-endian reader/writer; the TPKT length is big-endian
    Rdp.cs                Constants transcribed from MS-RDPBCGR
    Negotiation.cs        X.224 / T.125 and RDP_NEG_REQ / RDP_NEG_RSP
    Mcs.cs                Connect Initial/Response, Erect Domain, Attach User, join
    ClientPdu.cs          TS_UD_CS_CORE / SECURITY / NET / CLUSTER / USER
    RdpConnection.cs      Connection sequencing over TCP
  RdpClient/            WinUI 3 front end (Windows only)
  RdpClient.Cli/        Console handshake harness
tests/
  RdpClient.Protocol.Tests/
docs/                   Protocol notes, research, architecture
```

## Documentation

| Document | Contents |
| --- | --- |
| [docs/protocol.md](docs/protocol.md) | Field-by-field notes on each PDU, with spec sections |
| [docs/architecture.md](docs/architecture.md) | Project structure and design decisions |
| [docs/research.md](docs/research.md) | Analysis of `mstsc.exe` / `mstscax.dll` and what it revealed |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Security

This client sends credentials as UTF-16 in `TS_UD_CS_USER` **in the clear** over the classic RDP
handshake. On any untrusted network that is unacceptable. CredSSP/NLA is not implemented yet for
exactly this reason — until it is, only use this against hosts you control or over a trusted,
encrypted transport.

## Contributing

Issues and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

MIT. See [LICENSE](LICENSE).

RDP is a documented Microsoft protocol; this project contains no Microsoft code. You are
responsible for complying with the licence terms of any RDP host you connect to.