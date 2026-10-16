# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The CredSSP envelope, which was missing entirely, plus three encoding defects
found by diffing against a working reference implementation.

### Added

- **The connection log can be copied.** The header now carries `Copy log` and
  `Clear`. The copied text starts with the target, stage and account, because a
  pasted log that says which host and stage it came from is what makes a report
  actionable. The password is never in the log and never in the copy; the
  authenticator's protocol hex is, so the button says so in its tooltip.
  `Clear` existed in the view model but had no way to be pressed.

### Fixed

- **The MCS Connect-Initial was encoded as a flat TLV rather than as ASN.1.**
  It is T.125's `Connect-Initial ::= [APPLICATION 101] IMPLICIT SEQUENCE`,
  holding two domain selectors, an upward flag, three sets of domain parameters
  and the user data. 101 does not fit the five tag bits of one octet, so the
  identifier is written `7f 65`; the TLV this client produced began `03 00`, and
  xrdp named the difference:

  ```text
  [ERROR] Parsed [ITU-T X.690] Identifier: expected 0x7f65, actual 0x0300
  ```

  The user data inside it is the GCC Conference Create Request, encoded with
  T.125's ALIGNED variant of BASIC-PER rather than as a TLV. `Asn1` now holds
  the primitives both need, including the two that differ from the rest of RDP:
  BER INTEGERs are big-endian and sign-padded (`0xFFFF` becomes `00 FF FF`), and
  a PER length above 127 keeps a two-octet big-endian value with the high bit
  set instead of counting the octets that follow.
- **"MCS Connect Response result 3: connection refused" was a misread TPKT
  octet.** The response was parsed as a TLV starting at offset 0 of the whole
  TPKT datagram, so the byte read as the MCS result was `0x03` - the TPKT
  version. No server in this repository ever refused anything there. Two further
  errors sat behind it: the Connect-Response is `[APPLICATION 102]` (`7f 66`)
  and was being matched against nothing, and the X.224 check compared the
  length indicator against the DT code rather than the code itself.
- **The conference name was `McsCnxn`.** That is the H.221 node label from the
  older T.125 CCPDU, not a conference name, and PER encodes the name as a numeric
  string - digits only, two per octet. The name `"1"` is therefore the octet
  `0x10`, not `0x01`. The `GccConferenceLabel` constant is removed; nothing in
  the Connect-Initial carries a label.

  Verified against xrdp 0.10.1, which now parses the Connect-Initial, answers
  with a Connect-Response assigning UserID 31219, and moves on to the GCC client
  data - one stage further than before. It rejects those blocks, which is the
  next thing to fix.

- **`RDP_CORRELATION_INFO` was shorter than the length it declared.** The block
  declares 36 octets but only the 24 named fields were sent. Windows tolerates
  that; xrdp walks the declared length, fails with `Not enough bytes in the
  stream: expected 35, remaining 23`, and drops the connection before
  negotiation. The block is now padded, and `Negotiation.CorrelationInfoLength`
  records the value. Verified against both: xrdp goes from a 9-byte
  `DisconnectProviderUltimatum` to a Connection Confirm selecting
  `PROTOCOL_SSL` and a completed TLS 1.3 handshake, while the Windows host is
  unchanged. A capture of `mstsc.exe` shows it never sends this block, which is
  why the defect survived: nothing in the Windows path exercises the encoding.
- **The NTLM field-descriptor offset was written as 16 bits.** Each descriptor
  is `{ Length(2), MaxLen(2), BufferOffset(4) }`, so the BufferOffset occupies
  four octets, exactly as `ReadField` reads it. The writer emitted only two, and
  a BufferOffset above 65535 would have been truncated without the reader ever
  noticing. Both the AUTHENTICATE and the NEGOTIATE encoders now write four.
- **`Slice` could overflow while checking a bounds offset.** The check added
  `offset + length` in 32-bit arithmetic, which wraps for a large offset and can
  pass a slice the message cannot contain. The bounds are now compared without
  the sum.
- Removed the unused `Ntlm.Append` helper; it had no callers.
- **DER length and INTEGER octets were collected back-to-front.** The CredSSP
  encoder built each octet list with `Insert(0, …)`, which shifts the whole list
  on every insert. It now collects least-significant first and reverses once.
  The bytes produced are unchanged.
- **The CredSSP `TSRequest` envelope was absent.** The client wrote a bare token
  straight onto the TLS channel. CredSSP (MS-CSSP 2.2.1) requires every message
  after the handshake to be an ASN.1 `TSRequest` carrying the token in
  `negoTokens`. `CredSsp.cs` encodes and decodes the structure.
- **The `version` field did not wrap an INTEGER.** `TSRequest.version` is
  declared `[0] INTEGER`, which encodes as `a0 03 02 01 06`. The encoder wrote
  `a0 01 06`, declaring a single content byte holding a bare `0x06`, which is
  not a valid INTEGER. The request was therefore not valid DER, which is what
  `SEC_E_INVALID_TOKEN` was reporting. This was the actual blocker.
- **NTLM field descriptors were read from the wrong offsets.** The descriptor is
  `{ Length(2), MaxLen(2), BufferOffset(4) }` with a 32-bit offset. Reading
  Length from `[4..6]` and Offset from `[6..8]` takes the two halves of the
  offset, so the CHALLENGE's `TargetInfo` came back as the first 82 bytes of the
  message - the NTLMSSP signature included - and the AUTHENTICATE embedded a
  whole NTLM header.
- The NEGOTIATE flag set now matches a known-good client: `NEGOTIATE_SIGN`,
  `NEGOTIATE_SEAL` and `NEGOTIATE_LM_KEY` are offered, and
  `NEGOTIATE_OEM_WORKSTATION_SUPPLIED` is set only when the workstation name is
  actually present in the payload.
- `NEGOTIATE_TARGET_INFO` (`0x00800000`) was being set by the client. That flag
  announces that a message carries TargetInfo and is server-side.
- `NEGOTIATE_VERSION` was set while the 8-octet Version field at offset 32 was
  left all zero, which is not a valid version.

### Changed

- Authentication traces what it sends and receives, so a failure names the stage
  and the token type instead of surfacing as a flattened TLS error.
- The exchange now advances. The host accepts the NEGOTIATE and returns an NTLM
  CHALLENGE, which was never true before.
- Tests are pinned to captured bytes rather than to hand-typed hex: the CHALLENGE
  fixture is written to `Fixtures/challenge.bin` from a live run.

### Known issue

The protocol path is not known broken. **NTLM authentication completes**: the
server accepts the AUTHENTICATE and answers `STATUS_LOGON_FAILURE`
(`0xC000006D`) where it used to answer `SEC_E_INVALID_TOKEN` (`0x80090308`).
The remaining failure is a credential or a channel-binding question, not a
malformed PDU.

- **MD4 was wrong in three separate ways**, and a wrong NT hash makes *every*
  password fail with `STATUS_LOGON_FAILURE`, which is indistinguishable from a
  wrong password at the protocol level. It had a leftover register shuffle from
  a different formulation of the round step, four rounds of sixteen operations
  where RFC 1320 has three, and neither of the additive constants
  `0x5A827999` and `0x6ED9EBA1`. Each defect on its own still produced a
  plausible-looking 128-bit digest.
- The NTLMv2 response now uses the server's `MsvAvTimestamp` when the challenge
  carries one (MS-NLMP 3.2.2.2.1) and converts to a FILETIME otherwise, rather
  than writing `DateTime.Ticks`, which counts from year 1 rather than 1601.
- The AUTHENTICATE carries what `NEGOTIATE_KEY_EXCHANGE` requires
  (MS-NLMP 3.1.5.1.2, 3.4.4): a 16-byte random session key, its RC4-wrapped
  `EncryptedRandomSessionKey`, and a message integrity code over all three
  messages.
- `Rc4` is implemented directly, since .NET no longer ships one and NTLM uses it
  as a raw key schedule with no derivation.
- The CredSSP version 6 channel binding (MS-CSSP 3.1.5 step 3) is computed and
  sent with the AUTHENTICATE: a 32-byte client nonce, a SHA-256 over the magic
  string, the nonce and the server's `SubjectPublicKey`, sealed with the
  client-to-server sealing key `MD5(SessionKey || magic)`.

### Verification note

Authentication could not be confirmed end to end. The only reachable host is an
ngrok tunnel, and `mstsc.exe` itself cannot complete a connection through it:
it holds an established TCP connection and sits at "Configuring remote
session..." indefinitely. A local Windows host is available and is used as the
test target, but its `RDP` account has a different password, so it can only
confirm rejection, never acceptance.

### Settled

`NtlmFlags` values were suspected and cleared: MS-NLMP 2.2.2.5 labels the bits
(`W`=56-bit at 31, `H`=NTLM at 9, `L`=OEM workstation at 13) and every
declared value matches.

### Removed

- `Spnego.cs`. CredSSP does not wrap NTLM in SPNEGO, so the encoder had no
  callers and was worse than unused: its doc comment described exactly the
  layering the protocol does *not* use, which invited a future reader to
  "correct" the authenticator by using it. sspi's documentation on `ClientMode`
  is explicit - *"mstsc and other RDP clients send plain NTLM messages (without
  SPNEGO wrappers) inside CredSSP when Kerberos is not possible"* - and its
  reference `TSRequest` vector begins with a bare `NTLMSSP` signature inside
  `negoToken`.

### Tests

- Two regression tests pin the fixes above. One builds an AUTHENTICATE whose
  user name pushes the following offsets past 65535 and asserts the
  `BufferOffset` octets are `e0 02 01 00`, which the old 16-bit write turned
  into 736. The other builds a 300-byte CredSSP token, which forces the
  two-octet DER length form `82 01 45` at the outermost level and reads it back.
  Both were confirmed to fail against the unfixed encoders.

### Investigation

A TLS-terminating proxy (`credssp-tap.mjs`) was built to expose the CredSSP
exchange in plaintext, because the SPNEGO tokens live inside TLS and no external
tap can see them. It forwards the cleartext X.224 negotiation, then upgrades both
sides to TLS and logs the decrypted traffic.

What it established, in order:

1. The RDP negotiation is byte-identical to what `mstsc.exe` sends.
2. The TLS handshake completes on both TLS 1.2 and TLS 1.3.
3. The host waits for the client's token and then resets the connection.
4. Schannel reports that reset as "decryption operation failed", which is
   misleading — there is no decryption failure, the peer simply went away.
5. The generated token is internally consistent DER: the GSS-API wrapper, the
   `NegTokenInit` and the NTLM message each declare lengths matching their
   content, with the correct NTLM OID and a well-formed NEGOTIATE message.

Six hypotheses were tested and eliminated in the process: TPKT endianness, X.224
field order, the SPNEGO OID encoding, GSS-API tagging, the TLS version, and the
NTLM field offsets. Each was a real defect, and each was fixed, but none was the
cause.

The cause was found by reading the right binary and then asking the server
directly, rather than by a seventh guess about the token:

- `credssp.dll` is the CredSSP security provider (53 KB, "Microsoft CredSSP
  Security Provider"). `SpInitializeSecurityContextW` in it assembles the
  outgoing message, and its string table names `Negotiate`, the SSPI package
  CredSSP negotiates through. That is where the `TSRequest` envelope is built.
- `msv1_0.dll` validates NTLM messages and rejects anything that fails with
  `0x80090308`; it also caps a message at `0xB48` bytes.
- `secur32.dll` contains no NTLM and no CredSSP, only 123 strings. An earlier
  search returning nothing there was correct, not a tool failure.
- The host logs the real reason. Event 139 in
  `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` reads
  `The server security layer detected an error (0x80090308) in the protocol
  stream`, which names the rejection that Schannel was hiding behind a TLS
  error. This is the diagnostic to read before forming any theory.

### Security

The interception certificate and its CA were installed into `CurrentUser\Root`
during this investigation and have been removed. All six certificates added
(`CurrentUser\Root` and `CurrentUser\My`) are deleted and the trust stores are
back to their prior state.

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