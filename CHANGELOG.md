# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-16

External Security Protocol work. TLS now completes against a real RDP host; the
NTLM exchange that CredSSP needs is implemented but does not yet complete.

### Added

- **TLS channel** (`Security/TlsChannel.cs`): the handshake MS-RDPEA 3.1.5.1
  places on the same TCP connection, with `TERMSRV/<host>` SNI. The self-signed
  host certificate is accepted and then reported, because RDP does not
  chain-validate and the default policy would reject every real host.
- **Security mode selection** (`Security/RdpSecurity.cs`): maps the negotiated
  `SelectedProtocol` to TLS, CredSSP or none, and refuses an unknown protocol
  rather than downgrading.
- **NTLM** (`Security/Ntlm.cs`, `Security/Md4.cs`, `Security/NtlmAuthenticator.cs`):
  NEGOTIATE, CHALLENGE and AUTHENTICATE messages with an NTLMv2 response. MD4 is
  implemented because .NET does not ship it and NTLM specifies it.
- **SPNEGO** (`Security/Spnego.cs`): BER encoding and decoding for the
  GSS-API `NegTokenInit` / `NegTokenTarg` wrappers, plus SPNEGO error decoding.
- **CredSSP renegotiation** (`RdpConnection.RenegotiateInsideCredSspAsync`): the
  second `RDP_NEG_REQ` that MS-RDPEA 3.2.1.5.1.5 requires inside the
  authenticated channel.
- `rdpprobe` flags `--tls12`, `--tls-only` and `--credssp-only` to pin the
  security mode while diagnosing a host.
- Wrapped TLS and SPNEGO failures now report their root cause instead of the
  outermost message.

### Verified

Against a Windows Server 2025 host (`fDenyTSConnections=0`, port 3389):

- RDP negotiation selects `PROTOCOL_HYBRID_EX` and the client reports CredSSP.
- The TLS handshake completes on both TLS 1.3 and TLS 1.2, presenting the
  server's self-signed certificate.
- Requesting `PROTOCOL_SSL` alone is refused with `RDP_NEG_FAILURE` code 5
  (`SSL_REQUIRED_BY_SERVER`), so the host mandates NLA.

### Not working

The SPNEGO/NTLM exchange does not complete. The first token write is followed by
a TLS decryption failure, which indicates the host answered with an alert rather
than a challenge. The cause is not yet identified, so this is reported as a
failure rather than papered over.

### Not implemented

Unchanged from 1.0.0, and all still ahead of the login screen:

- CredSSP RSA key exchange and session key derivation (MS-RDPBCGR 5.3.2)
- Encryption of MCS traffic (RC4 / AES)
- Capability exchange (2.2.7), including the `Demand Active` / `Confirm Active`
  pairs that begin the connection
- Early User Authorization (2.2.10.2) and the logon-information PDUs
- The graphics pipeline and input needed to draw a framebuffer at all

### Fixed

- The SPNEGO mechanism OID was double-wrapped and declared a five-octet length
  for six octets of content, which made every token malformed.
- `thisMech` in the GSS-API wrapper is tagged APPLICATION (`0x60`), not
  CONTEXT-specific; the two are not interchangeable.

## [1.0.0] - 2026-10-16

First release. The RDP connection sequence, implemented from Microsoft's public
Open Specifications, verified byte-for-byte against a live Windows RDP server.

### Added

- **X.224 / T.125 connection request** (MS-RDPBCGR 2.2.1.1) with TPKT framing.
- **RDP negotiation exchange** (2.2.1.1.1, 2.2.1.2.1): `RDP_NEG_REQ` / `RDP_NEG_RSP`,
  optional correlation block with `CORRELATION_INFO_PRESENT`.
- **MCS Connect Initial / Connect Response** (2.2.1.3.4, 2.2.1.3.5) including the
  GCC Conference Create Request.
- **Client data blocks** (2.2.1.3.4.1–.5): `TS_UD_CS_CORE`, `TS_UD_CS_SECURITY`,
  `TS_UD_CS_NET`, `TS_UD_CS_CLUSTER`, `TS_UD_CS_USER`.
- **MCS domain and channel setup** (2.2.1.3.6–.8): Erect Domain Request,
  Attach User Request, Channel Join Request, Send Data Request framing.
- **T.125 Disconnect Request** for orderly close.
- WinUI 3 desktop app with a connection form and a timestamped handshake log.
- `rdpprobe` console harness for exercising the handshake without the GUI;
  reads the password from `RDP_PASSWORD` and never echoes it.
- Protocol-layer unit tests pinned to bytes captured from `mstsc.exe`.
- Documentation site, logo, and application icon set.

### Platform

- Windows on **x64**, **ARM64** and **x86**.
- Windows only: WinUI 3 has no macOS or Linux implementation. The protocol core
  targets plain .NET and carries no UI dependency, so it can be reused from a
  cross-platform front end if one is written.

### Not implemented

Stated plainly so nobody mistakes this for a working desktop viewer:

- RSA key exchange and RC4/AES session keys (2.2.1.4.3, 5.3.2)
- CredSSP / NLA — TLS + SPNEGO + NTLM (MS-RDPEA)
- Capability set exchange (2.2.7)
- Bitmap, pointer and order graphics pipeline (2.2.9)
- Keyboard and pointer input (2.2.8)
- Virtual channel data: clipboard, drive, audio (2.2.6)

### Security

Credentials are transmitted as UTF-16 in `TS_UD_CS_USER` over the classic RDP
handshake, in clear. CredSSP is not implemented, so use only against hosts you
control or over a trusted, encrypted transport.

### Fixed during development

These were found by comparing emitted bytes against a recorded `mstsc.exe`
exchange; each produced a malformed PDU that a server answered with an immediate
reset.

- TPKT length is **big-endian** while the rest of the connection sequence is
  little-endian.
- The X.224 length indicator precedes the TPDU code; TPKT orders its length last.
- `TS_UD_CS_*` headers are 16-bit little-endian values, not single bytes.
- `TS_UD_CS_*` TLV headers are 6 bytes: type(2), flags(2), length(2).
- MCS integers are plain fixed-width values with no T.125 selector bits.
- The GCC conference name length is counted in UTF-16 code units, not bytes.

[1.0.0]: https://github.com/adyoi/RdpClient/releases/tag/v1.0.0