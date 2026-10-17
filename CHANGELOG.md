# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The CredSSP envelope, which was missing entirely, plus the MCS client data and
channel-setup encodings, which xrdp rejected outright. The connection now
completes the MCS channel join against xrdp, and reports only what the server
actually confirmed.

### Added

- **The connection log can be copied.** The header now carries `Copy log` and
  `Clear`. The copied text starts with the target, stage and account, because a
  pasted log that says which host and stage it came from is what makes a report
  actionable. The password is never in the log and never in the copy; the
  authenticator's protocol hex is, so the button says so in its tooltip.
  `Clear` existed in the view model but had no way to be pressed.
- **`SendClassicUserBlock`** exposes the classic-RDP user data block, off by
  default. See the security note below.
- **Parsing for the server's replies.** `AttachUserConfirm` and
  `ChannelJoinConfirm` are read and interpreted, and the client stops with the
  server's reason when either refuses.
- **The mandatory capability exchange is implemented** (MS-RDPBCGR 2.2.1.13).
  `Capability.cs` builds and parses the Share Control Header, the General
  Capability Set, the server's Demand Active PDU and the client's Confirm Active
  PDU, and `Mcs.ParseSendDataIndication` reads the MCS fragments a server PDU
  arrives in. `HandshakeStage` gains `CapabilityExchanged` and `ActiveConfirmed`.
  Unit-tested, but **not verified against a live server** - see the note at the
  end of this release.
- **The handshake is bounded.** `RdpConnectionOptions.Timeout`, 30 seconds by
  default, `rdpprobe --timeout <seconds>`. Every read in the sequence is a
  blocking socket read, so a server that stopped mid-sequence left the client
  waiting forever: it had to be killed rather than returning, and the server log
  was completely clean, so there was nothing to diagnose. A timeout turns the
  same situation into `the server stopped responding after 12s; the last thing
  that worked was the channel joins; it never sent the Demand Active PDU`.
- **`--skip-channel-join`** announces `RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN` and
  sends no Channel Join Requests. Off by default, and not verified to help; see
  the note at the end of this release.

### Fixed

- **The client joined one channel where the server expected ten.** A client sends
  one Channel Join Request per static virtual channel it offered, plus one for the
  MCS user channel and one for the global channel. This client sent only the
  global channel, so xrdp was left reading a join that would never arrive. Its
  whole error chain was the symptom:

  ```text
  [ERROR] Processing [ITU-T T.25] ChannelJoinRequest failed
  [ERROR] [MCS Connection Sequence (TLS)] receive channel join request failed
  [ERROR] xrdp_sec_incoming: xrdp_mcs_incoming failed
  [ERROR] xrdp_rdp_incoming: xrdp_sec_incoming failed
  ```

  All four are gone. Measured from xrdp's `handle_channel_join_requests`, which
  expects `channel_list->count + 2` joins and sets `self->chanid = 1001`; static
  channel ids are positional at 1004 + N, which FreeRDP and xrdp both derive from
  the global channel id. xrdp's `Expected N channel join PDUs but got N` is only
  a warning, so its absence is what shows the count matched. The documentation
  claimed this state was expected; it was not, and it said so.
- **A Channel Join Confirm for the wrong channel was reported as a success.** The
  result octet alone was taken as proof and whatever channel id followed was
  echoed back. The Confirm now has to name the channel that was requested, which
  is the same "reported success it never verified" defect this connection
  sequence was rewritten to remove.
- **The Channel Join Confirm's optional channel id was read unconditionally.**
  Opcode bit `0x02` marks it present, and the bit means something different in
  each Confirm: xrdp sets it for the *initiator* in the Attach User Confirm and
  for the *channel id* in the Channel Join Confirm, having written initiator and
  requested unconditionally beside it.
- **The MCS PDUs carried the wrong MS-RDPBCGR section numbers.** 2.2.1.3.x are
  the client data blocks; the domain PDUs are 2.2.1.5 (Erect Domain Request),
  2.2.1.6 and 2.2.1.7 (Attach User Request and Confirm) and 2.2.1.8 and 2.2.1.9
  (Channel Join Request and Confirm), with 2.2.1.3 the Connect Initial and
  2.2.1.4 the Connect Response. The prose had been corrected and the source files
  had not. Verified against the specification's own `toc.json`.
- **`ClientPdu`'s class documentation still described `TS_UD_HEADER` as
  type/flags/length.** There is no flags field, and that wrong description is
  what the header's six-octet defect came from in the first place.
- **`TS_UD_CS_NET` accepted more than 31 static channels.** MS-RDPBCGR 2.2.1.3.4
  caps `channelCount` at 31, and a server is entitled to read only 31
  definitions.
- **The client reported success it had not verified.** This was the most
  serious defect in the project. The Erect Domain, Attach User and Channel Join
  requests were written and `ConnectAsync` returned `Complete` without reading
  a single reply, so the CLI printed `RESULT: MCS channel joined.` against a
  server that had rejected the first PDU. xrdp's log at the time reads:

  ```text
  [ERROR] Parsing [MS-RDPBCGR] GCC Conference Create Request client data field
          Not enough bytes in the stream: expected 32764, remaining 308
  [ERROR] Processing [ITU-T T.125] ErectDomainRequest failed
  [ERROR] [MCS Connection Sequence] receive erect domain request failed
  ```

  Every stage now waits for the reply that proves it. The Attach User Confirm is
  not optional bookkeeping: it is the only place the server states the user id
  it assigned, and the Channel Join Request has to carry that id.
- **The `TS_UD_HEADER` was 6 bytes instead of 4.** MS-RDPBCGR 2.2.1.3.1 defines
  it as type(2) and length(2) with **no flags field**, and every client data
  block carries one. Writing an extra flags octet shifted every payload field by
  two.
- **`TS_UD_CS_CORE` was written as though it had no header at all.** It has one
  like every other block, which is what left it 36 octets short of the 234 the
  specification lays out. The missing octets were the header, the 64-byte
  `clientDigProductId` (written as a 4-byte field), and the trailing
  orientation and scale factors. Two fields that do not exist in the structure -
  `clientColorDepth` and `clientPostBeta2ColorDepth` - were written in their
  place. CORE is now the 234-octet block a real client sends, pinned against
  FreeRDP's `gcc_write_user_data_header(s, CS_CORE, 234)`.
- **Every declared `TS_UD_HEADER.length` covered only a fixed portion.** The
  length is the size of the whole block including the header, and a reader walks
  it to find the next block, so declaring less than is sent desynchronises
  everything after it with no diagnostic. `NET` declared 8 while sending 114.
  Lengths are now patched after the payload is written, so the two cannot drift
  apart again.
- **`CHANNEL_DEF` was written with a spurious length prefix.** It is a fixed
  12-octet structure - an 8-octet name and a 4-octet options mask - with no
  length octet, so every channel entry was 13 bytes and `NET` was 8 bytes longer
  than the count it declared. It is now `12 * channelCount + 8`.
- **The MCS domain PDUs were sent bare.** Erect Domain, Attach User and Channel
  Join are T.125 DomainMCSPDUs and each travels in TPKT + X.224 Data TPDU, as
  the annotated PDUs in MS-RDPBCGR 4.1.5 and 4.1.6 show. Sent bare, xrdp could
  not find a TPKT header at all.
- **The opcode octet was the PDU code rather than the shifted CHOICE index.**
  It is `(choice << 2) | options`, with the choice in the top six bits. Erect
  Domain is choice 1 and so is `0x04`, not `0x05`. The old values came from a
  different numbering in MS-RDPBCGR 3.3.5.2 and landed on unrelated PDUs.
- **Erect Domain wrote its two fields as raw values rather than PER integers.**
  A zero is the two octets `01 00`, because a PER integer carries its own length
  determinant.
- **The MCS global channel was 1007.** It is **1003**; 1007 is the H.225.0 RTP
  channel number, and a client that joins it joins a channel no server created.
- **The Connect Response walk skipped the ignored `connectPDU` length as a
  single octet.** It must be ignored as a *value* but still occupies one or two
  octets, so it is now stepped over as a variable-width PER field.
- **`RDP_CORRELATION_INFO` was shorter than the length it declared.** The block
  declares 36 octets but only the 24 named fields were sent. Windows tolerates
  that; xrdp walks `1 + 2 + 16 + 16` octets after the type and aborts the
  connection before negotiation. The block is now padded, and
  `Negotiation.CorrelationInfoLength` records the value. A capture of
  `mstsc.exe` shows it never sends this block, which is why the defect survived:
  nothing in the Windows path exercises the encoding.
- **The NTLM field-descriptor offset was written as 16 bits.** Each descriptor
  is `{ Length(2), MaxLen(2), BufferOffset(4) }`, so the BufferOffset occupies
  four octets, exactly as `ReadField` reads it. The writer emitted only two, and
  a BufferOffset above 65535 would have been truncated without the reader ever
  noticing.
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
- **The GCC `connectPDU` length added a flat 14 octets of overhead.** It counts the
  client data, twelve octets of fixed framing, **and the client-data length field
  itself**, and that field is one octet while the client data stays below 0x80. The
  declared length was therefore one too large for any client data under 128 bytes,
  which does not occur in a real connection but is wrong. It is now
  `clientData.Length + 12 + PerLengthOctets(clientData.Length)`. Measured in
  `mstscax.dll`, which builds it as `(0xe - (uint)(uVar3 < 0x80)) + uVar3` - +14 at
  or above 0x80 and +13 below - which agrees with that formula at every input,
  including the narrow band where the total crosses 0x80 while the client data does
  not.

### Known gaps

- **The Demand Active PDU never arrives from this xrdp, so the capability
  exchange is unverified end to end.** The MCS sequence completes - xrdp accepts
  all ten channel joins, answers every Confirm, and logs
  `xrdp_load_keyboard_layout`, which it only does once MCS completes - and then
  xrdp sends nothing and waits. From its source that is not specific to one
  strategy: `handle_channel_join_requests` does a `libxrdp_force_read` after
  every join, and `libxrdp_process_data` does another before it will send the
  Demand Active, so a client sending ten joins blocks xrdp on the first and a
  client sending none blocks it on the second. Both were tried; both are silent.
  What a client is supposed to send at that point, if anything, is still unknown.
  A `tools/rdp-tap.mjs` capture of `mstsc` was the obvious next measurement and
  did not settle it, because the MCS PDUs arrive inside TLS 1.3 and cannot be
  read without the session keys.
- **`TS_UD_CS_CORE` is 234 octets on the strength of the specification and
  FreeRDP, not a capture.** `mstscax.dll` builds the client data blocks through a
  COM vtable one hop beyond its only caller. It is pinned by a test now, which
  pins the arithmetic and not a measurement.
- **The static channel list is a guess.** `rdpdr`, `cliprdr` and `drdynvc` exist
  in `mstscax.dll` as UTF-16 strings; `rdpgfx`, `urbout`, `encomsp` and `audin`
  are absent from that binary entirely.
- **NTLM end to end is still unverified**, and needs a Windows host or a server
  that offers CredSSP.

### Security

- **The classic-RDP user data block is no longer sent by default.** It puts a
  password on the wire in UTF-16 in the clear, and MS-RDPBCGR does not define it
  at all - xrdp answers `TS_UD_HEADER type 0xc00e is unknown (ignored)`, so the
  client was transmitting a credential the server was about to discard.
  `SendClassicUserBlock` makes it opt-in, which is the point at which the
  README's warning about cleartext credentials applies.
- `TS_UD_CS_CORE` reported zero physical desktop dimensions, which is invalid
  rather than merely ignored: xrdp logged
  `Physical desktop dimensions (0x0) are invalid` and sized the session window
  to nothing. It now reports a 4:3 desktop in millimetres.

### Changed

- The MCS global channel is joined as **1003**, and the join is only reported
  complete once the server's Channel Join Confirm has been read. Every channel is
  now joined and every Confirm checked, not just this one.
- The static channel list is now documented as **unverified**. Searching
  `mstscax.dll` finds `rdpdr`, `cliprdr` and `drdynvc` as UTF-16 strings, but
  `rdpgfx`, `urbout`, `encomsp` and `audin` appear nowhere in that binary in
  either encoding, so the other clients are registered from somewhere a string
  search does not reach. The list is a guess and now says so.
- Authentication traces what it sends and receives, so a failure names the stage
  and the token type instead of surfacing as a flattened TLS error.
- The exchange now advances. The host accepts the NEGOTIATE and returns an NTLM
  CHALLENGE, which was never true before.
- Tests are pinned to captured bytes rather than to hand-typed hex: the CHALLENGE
  fixture is written to `Fixtures/challenge.bin` from a live run.

### Verified

Against xrdp 0.10.1 in WSL (Debian 13, port 3390, `--tls-only`):

```text
negotiated version 0x00000001, SelectedProtocol 0x00000001
Tls13, subject 'CN=runnervm0xl3a.localdomain' (self-signed certificate accepted)
sent MCS Connect Initial (561 bytes)
MCS accepted (conference 0), UserID 31219, ServerNodeID 31219
sent Erect Domain Request (12 bytes)
sent Attach User Request (8 bytes)
attached as MCS user 1012
joined MCS channel 1003
```

xrdp's log for the same run contains no parse error and no unknown block; the
first MCS-related line is the Channel Join reading the client's next request and
hitting the client's own disconnect, which is the boundary before the
capability exchange exists.

### Known issue

NTLM authentication against a Windows host reaches `STATUS_LOGON_FAILURE`, and
NTLM is not exercised against xrdp, which does not offer CredSSP here.

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