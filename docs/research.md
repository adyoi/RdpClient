# Research: what Windows ships, and what it revealed

This document records the analysis that shaped the implementation, along with
what it could not establish. It is included because the negative results matter
as much as the positive ones.

## The two binaries

`mstsc.exe` is not the client. It is a thin host process.

| | `mstsc.exe` | `mstscax.dll` |
| --- | --- | --- |
| Size | 1,105,920 bytes | 9,093,120 bytes |
| PE resources | 6 | 4 |
| Dialog / menu / string-table resources | **none** | **none** |
| Embedded type library | 2,092 bytes | **80,568 bytes** |
| Version | 10.0.26100.33158 | 10.0.26100.33296 |

Both are Windows 11 / Server build **26100** (24H2).

Static PE resource inspection found no `RT_DIALOG`, `RT_MENU`, `RT_STRING` or
`RT_GROUP_ICON` entries in either file. Reverse-engineering `mstsc.exe` alone
would therefore have been close to useless: the interface and the protocol logic
live in `mstscax.dll`, a COM ActiveX control that `mstsc.exe` merely hosts.

The PDB reference in `mstscax.dll` is `mstscax.pdb`, GUID
`129b033f-a3ac-3985-e30e-454fd95144e0`, age 1. The PDB is not present on the
system, so original symbol names were unavailable.

## Function inventory

Ghidra 12.1.4 headless decompilation of `mstscax.dll`:

| Measure | Value |
| --- | --- |
| Procedures | **22,685** |
| Defined strings | **20,552** |
| Image base | `0x180000000` |
| `.text` | 6,676,480 bytes |

22,685 functions for an 8.7 MB library is consistent with a complete RDP client:
connection sequencing, negotiation, four graphics codecs, the bitmap cache,
virtual channel managers and a COM automation surface.

## The COM type library

The 80,568-byte `TYPELIB` resource is the most useful artefact found, because it
documents the control's **public** API without any decompilation. Names were
recovered from the name pool; this library stores them as 8-bit strings rather
than UTF-16.

Interfaces:

```text
IMsRdpClient                        IMsRdpClient2 .. IMsRdpClient9
IMsRdpClientAdvancedSettings        IMsRdpClientAdvancedSettings2 .. 8
IMsRdpClientNonScriptable           IMsRdpClientNonScriptable2 .. 8
IMsRdpClientTransportSettings
IMsRdpClientSecuredSettings
IMsRdpDevice            IMsRdpDeviceCollection
IMsRdpDriveCollection   IMsRdpCameraRedirConfigCollection
IMsRdpPreferredRedirectionInfo
```

Connection lifecycle members: `Connect`, `ConnectWithEndpoint`,
`ConnectToAdministerServer`, `ConnectToServerConsole`, `Disconnect`,
`ExtendedDisconnectReason`, `ExtendedDisconnectReasonCode`.

Protocol and feature members that map to concrete subsystems:

| Member | Subsystem |
| --- | --- |
| `PortablePassword`, `PortableSalt` | Restricted-admin / CredSSP |
| `RdpFileContents`, `ServerStartProgram` | `.rdp` parsing, RemoteApp |
| `RdpdrClipCleanTempDirString`, `RdpdrClipPasteInfoString` | Device redirection, clipboard |
| `RdpdrLocalPrintingDocName` | Device redirection, printing |
| `ConnectionBarText`, `ConnectionBarShowPinButton` | Connection bar UI |
| `DesktopWidth`, `DesktopHeight`, `ColorDepth`, `SmartSizing` | Graphics pipeline |

These are the seams a reimplementation needs, and each is described in the
public specification.

## Strings that confirmed handshake details

A targeted search for protocol markers found:

| String | Address | Significance |
| --- | --- | --- |
| `Cookie: mstshash=%s\r\n` | `0x1806b1f18` | The X.224 **routing token** (2.2.1.1.2). Load balancers parse it; the server must ignore it. |
| `Cookie: .ASPXAUTH=` | `0x18077b520` | Gateway authentication cookie |
| `CredSSP`, `CredSSP-EX`, `CREDSSP` | several | NLA support is present |
| `SYSTEM\CurrentControlSet\Control\Lsa\Credssp` | `0x1807c2700` | NLA is gated on registry policy |
| `credssp disabled by default.` | `0x180799b30` | CredSSP is opt-in in the control |

No `McsCnxn` literal appeared in the string inventory. Ghidra only reports
strings it defines as `Data`; the conference name may be stored in a form this
inventory does not classify. Its value comes from the specification.

## What this research did not settle

- **No runtime observation.** The client's behaviour was not traced live. Every
  conclusion here is static, and none of it establishes how the client behaves
  when actually connected.
- **No source-level truth.** Names come from a type library, which is the
  intended public surface, not the implementation.
- **The protocol was therefore written from MS-RDPBCGR**, not inferred from
  these binaries. The analysis served to identify the right target, confirm the
  subsystem layout, and validate field semantics.

## How the implementation was actually verified

Static analysis could not confirm a single byte of the wire format. That came
from a different source: `mstsc.exe` was pointed at a logging TCP proxy in front
of a local Windows RDP host, and the recorded exchange became the test fixture.

```text
client → server   03 00 00 13 | 0e e0 00 00 00 00 00 | 01 00 08 00 | 0b 00 00 00
server → client   03 00 00 13 | 0e d0 00 00 12 34 00 | 02 2f 08 00 | 08 00 00 00
```

That single capture exposed three framing defects that had each produced an
immediate connection reset, and it is why the encoders are now pinned by tests.
The server selected `PROTOCOL_HYBRID_EX`, so CredSSP is required before MCS
begins; the client reports that boundary rather than sending an MCS Connect
Initial it knows the server will reject.