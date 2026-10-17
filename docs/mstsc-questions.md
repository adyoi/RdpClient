# Target questions for REA against mstsc

Scope: what this repository still cannot prove from a spec or from xrdp, and
that only `mstsc.exe` / `mstscax.dll` can settle.

## Status

One session of `mstscax.dll` (Ghidra 12.1.4, ~10 min) answered part of this. The
rest is still open; do not re-derive the answered part.

| | Question | Result |
| --- | --- | --- |
| Q1 | Is `TS_UD_CS_CORE` 234 octets? | **Open.** Not reached - see below |
| Q2 | Default channel list and options | **Open.** Names are not stored as ASCII |
| Q3 | Channel Join initiator source | **Open.** |
| Q4 | How many channels are joined, in what order? | **Open.** |
| Q5 | `desktopPhysicalWidth` / `Height` | **Open.** |
| Q6 | What follows the Channel Join? | **Partly.** Demand Active per the spec, not confirmed here |

**Settled as a side effect:** the GCC Conference Create Request byte layout.
`FUN_180163600` builds it from immediates - `00 05 00 14 7c 00 01`, the PER
length, `00 08 00 10 00 01 c0 00 44 75 63 61`, the PER client-data length, then
the blocks copied verbatim - which matches `Mcs.BuildConferenceCreateRequest`
octet for octet. That function also produced the `connectPDU` length defect now
fixed and recorded in AGENTS.md invariant 16.

**Why Q1 is still open:** the client data blocks are not written in the caller.
`FUN_18015f294` (1820 octets, the only caller) reaches them through COM vtable
slots - `*(code **)(*plVar2 + 0x248)` and `+ 0x2b8` - so the `CS_CORE` writer is
at least one more hop out. That caller has no `0xEA` and no `0xC001` immediate,
which is itself informative: the block type and length are built elsewhere.

**Why Q2 is still open:** `rdpdr`, `cliprdr`, `rdpgfx`, `urbout`, `encomsp` and
`audin` do not appear as contiguous ASCII anywhere in the binary. Only
`drdynvc` matches once, at `0x1806ab3f0` in `.rdata`, and the eight `rail` hits
are substrings of ordinary words. The names are most likely UTF-16, so the next
attempt should search for `72 00 64 00 70 00 64 00 72 00`.

## Which binary answers what

| Question | Binary |
| --- | --- |
| Client data block layout and sizes | `mstscax.dll` (the COM control holds the logic) |
| Channel join sequence and channel ids | `mstscax.dll` |
| CredSSP `TSRequest` assembly | `credssp.dll` |
| NTLM message construction | `msv1_0.dll` |

`mstsc.exe` is a thin host; anything about protocol encoding is in
`mstscax.dll`.

## Q1 - Is TS_UD_CS_CORE 234 octets?

This is the one number this repository inferred rather than measured. It comes
from FreeRDP's `gcc_write_user_data_header(s, CS_CORE, 234)` and from summing
MS-RDPBCGR 2.2.1.3.2's field table. Both are evidence, neither is a capture.

Find the client core data writer and report:
- the declared length value written into the TS_UD_HEADER,
- the total bytes written after it,
- whether the 4-byte header itself is emitted.

If the declared length and the bytes written disagree, that is the defect class
this repository just fixed eight times in a row, and it should be reported as
such rather than as a number.

## Q2 - Which virtual channels does a default client offer, and with what flags?

`ClientPdu.DefaultChannels()` currently offers rdpdr, cliprdr, rdpgfx, rail,
drdynvc, audin, encomsp, urbout. MS-RDPBCGR caps `channelCount` at 31, and
each CHANNEL_DEF is a fixed 12 octets.

Report the channel list a default `mstsc` connection actually sends, with the
options flags per channel. If the default set differs, the encoder and its
`12 * channelCount + 8` test should follow the real client rather than a guess.

## Q3 - Does the Channel Join use the user id from the Attach User Confirm?

The repository now reads the Attach User Confirm and uses that id, PER-offset
by 1001. This was verified against xrdp, which writes its user id raw with no
offset. Windows may differ, and this is exactly the kind of question only the
real client can answer.

Report what mstsc puts in the Channel Join initiator, and where the value comes
from - a constant, the Confirm, or something else.

## Q4 - How many channels does mstsc join, and in what order?

The client currently joins only the MCS global channel 1003. xrdp then reads
the next Channel Join and hits the client's disconnect, which is the expected
boundary before the capability exchange.

A real client must join the user channel as well. Report the full ordered list
and the ids, so the stopping point in this repository can be described
precisely rather than as "the next PDU is Demand Active".

## Q5 - What are desktopPhysicalWidth and desktopHeight?

Zero is invalid and xrdp rejected it. This repository now sends 270 x 203 mm
as a plausible 4:3 default, which is a guess with no evidence behind it.

Report the values a default mstsc sends. If they are read from the display, say
so, because that is a different kind of answer from a constant.

## Q6 - What follows the Channel Join?

**Answered 2026-10-17, and not from mstsc: the Client Info PDU.** The tap
capture could not supply this - the MCS PDUs travel inside TLS 1.3 - so the
answer comes from xrdp's sources plus a live probe against them:

- MS-RDPBCGR 1.3.1.1 places the Secure Settings Exchange between the channel
  join confirms and the Capabilities Exchange: the client sends the Client Info
  PDU (TS_INFO_PACKET, 2.2.1.11); it gets nothing back but the server's
  behaviour changes.
- xrdp is the proof on the server side. `xrdp_sec_recv`
  (libxrdp/xrdp_sec.c) dispatches each slow-path PDU on its TS_SECURITY_HEADER
  flags, and only the `SEC_INFO_PKT` branch - which consumes the logon fields,
  `xrdp_sec_process_logon_info` - calls `xrdp_sec_send_lic_response` and then
  `return -1`, the special error `libxrdp_process_data` treats as "send the
  Demand Active PDU". Anything else a client puts there falls out of the
  dispatch and the server keeps waiting.
- Measured: the probe sent one 296-octet Client Info PDU on the MCS global
  channel (1003); xrdp logged `xrdp_load_keyboard_layout` (the logon fields
  consumed) and answered with a 20-octet Licensing PDU and then a Demand Active
  PDU carrying 14 capability sets. The client skipped the licensing PDU by
  structure (`SEC_LICENSE_PKT` flag, `flagsHi == 0`, `wMessageSize` preamble)
  and answered the Demand Active with a Confirm Active that produced no
  `TS_CONFIRM_ACTIVE_PDU` error in `/var/log/xrdp.log`.

The two theories this question already collected - a larger join count, then
`RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN` - were both wrong, and AGENTS.md carries
 their retraction. Neither join count nor skip flag makes xrdp talk; the
Client Info PDU does.

## Method notes

- One `open_binary` per binary, then many queries against the same session.
  `mstscax.dll` is 9 MB; auto-analysis is expensive.
- Prefer a string or xref search to find the region before asking for
  pseudocode, so the decompiler work lands on the right function.
- Where a function cannot be recovered, say so. A wrong guess reported as a
  finding is worse than an explicit unknown: the previous round of this work
  inherited seven defects that each looked plausible.
