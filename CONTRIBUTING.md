# Contributing

Thanks for looking at this. The connection sequence works; most of the protocol
does not yet, so there is a lot to build.

## Getting set up

```powershell
git clone https://github.com/adyoi/RdpClient.git
cd RdpClient
dotnet restore
dotnet build
dotnet test
```

To run the app you need the WinApp CLI:

```powershell
winget install Microsoft.WinAppCLI
winapp run
```

## Before you open a pull request

```powershell
dotnet build -warnaserror
dotnet test
```

`RdpClient.Protocol` is compiled with `TreatWarningsAsErrors`. If the build
fails on a warning you cannot fix cleanly, fix the warning rather than widening
`NoWarn`.

## Working on the protocol

**Transcribe from MS-RDPBCGR, do not infer from captured traffic.** The
specification is the authority. Captured bytes are how you *check* an encoder,
never how you decide what one should be.

Three rules that are easy to get wrong and have each caused an immediate
connection reset:

1. The TPKT length is **big-endian**. Everything else is little-endian.
2. X.224 puts the **length indicator before** the TPDU code. TPKT puts its
   length last.
3. `TS_UD_CS_*` discriminators are **16-bit**, and the `NET` / `CLUSTER` /
   `USER` blocks carry a 6-byte TLV header.

`docs/protocol.md` has the field tables and the reasoning.

### Adding a PDU

- Put byte-level encoders in the matching file under `RdpClient.Protocol`.
- Keep the protocol core free of UI types.
- Add a test. For encoders, assert exact bytes. The existing suite is pinned to
  a recorded `mstsc.exe` exchange, so follow its style.
- Reference the governing MS-RDPBCGR section in a comment.

## Testing against a real server

`rdpprobe` will connect to any RDP host:

```powershell
$env:RDP_PASSWORD = '...'
dotnet run --project src/RdpClient.Cli -- --host 192.0.2.10 --user alice
```

Add `--hex` to dump transmitted PDUs. Do not commit `.rdp` files or anything
containing credentials; `.gitignore` already excludes them, but keep an eye out.

Expect the connection to stop after negotiation on any modern host, because
CredSSP is not implemented yet. That is the current expected behaviour, not a
regression.

## Commit messages

Conventional Commits, lowercase type prefix:

```text
feat(negotiation): parse RDP_NEG_FAILURE failure codes
fix(codec): write TPKT length big-endian
docs(protocol): clarify the X.224 length indicator
```

## Reporting bugs

Include the `rdpprobe` output with `--hex`, the host's behaviour, and the
MS-RDPBCGR section you believe applies. If a captured exchange is useful, say
which side sent which bytes.

## Security

Do not open a public issue for anything that looks like a vulnerability. Use
GitHub's private vulnerability reporting on the Security tab.

## Licence

By contributing you agree that your work is licensed under the MIT licence in
`LICENSE`.