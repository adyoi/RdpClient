# A second RDP server in WSL, for testing

A client that is only ever tested against Windows is a client whose encoding
bugs stay hidden. Windows tolerates malformed PDUs that other servers reject,
and `mstsc.exe` and FreeRDP both skip optional structures, so a wrong encoder
can pass every Windows test and still be wrong.

xrdp in WSL is a cheap second opinion. It is strict about declared lengths, it
names the structure it was parsing when it refuses a PDU, and it speaks TLS, so
one xrdp instance exercises the whole path from `X.224` to `MCS Connect Initial`.
That is how the `RDP_CORRELATION_INFO` defect was found: Windows negotiated fine
with a 24-octet block, and xrdp answered `expected 35, remaining 23`.

This page stands up that second server. It was written on Windows 11 with
WSL 2, Ubuntu 26.04, XFCE and xrdp 0.10.1; the commands are written for Bash
inside the distro and for PowerShell on the Windows side.

## Before you start

| Requirement | Check |
| --- | --- |
| WSL 2 with a distro | `wsl --list --verbose` |
| Virtualisation enabled | BIOS/UEFI, and `VirtualMachinePlatform` on |
| Administrator rights | enabling the WSL features and `winget` installs |

Port **3389 is usually already taken on Windows** by TermService, so this
document uses **3390** throughout. Pick any port the host is not using.

## 1. Install a distro

```powershell
wsl --list --online                 # what this host offers
wsl --install -d Ubuntu-26.04       # or Debian, Ubuntu-24.04, ...
wsl --list --verbose                # expect VERSION 2 and State Running
```

If `wsl --install` refuses, the optional features are off and an elevated shell
is needed:

```powershell
Start-Process powershell -Verb RunAs   # accept the UAC prompt
```

First boot runs `apt upgrade -y` in the background and holds the dpkg lock. An
install attempted in parallel fails with:

```text
E: Could not get lock /var/lib/apt/lists/lock. It is held by process 505 (apt)
```

Wait for it rather than killing dpkg mid-transaction:

```bash
while pgrep -x apt-get >/dev/null || pgrep -x dpkg >/dev/null; do sleep 20; done
```

## 2. Enable systemd

xrdp is a service, so it needs an init system. Ubuntu 24.04 and later already
boot systemd as PID 1; check before changing anything:

```bash
ps -p 1 -o comm=        # systemd -> nothing to do
```

If it prints `init`, add the setting and restart the distro:

```bash
printf '[boot]\nsystemd=true\n' >>/etc/wsl.conf
# from Windows: wsl --shutdown, then start the distro again
```

## 3. Choose a desktop

The desktop is what makes the RDP session worth looking at; xrdp only supplies
the display. Lightweight options behave better inside WSL because a VM has
less memory than a machine with a GPU.

| Desktop | Packages | Idle RAM | Notes |
| --- | --- | ---: | --- |
| **XFCE** (recommended) | `xfce4 xfce4-terminal` | ~250 MB | Starts in about two seconds, uses `startxfce4`, smallest dependency set of the full desktops |
| LXQt | `lxqt` | ~200 MB | Also light; `startlxqt` |
| MATE | `mate-desktop-environment` | ~350 MB | GNOME 2 fork, conventional layout |
| openbox + xterm | `openbox xterm` | ~60 MB | Not a desktop. Enough to prove a session and see protocol errors |
| GNOME | `gnome` | ~700 MB | Works, but slower to start and heavier than useful here |
| KDE Plasma | `kde-plasma-desktop` | ~900 MB | Same; not recommended under WSL |

Install the one you want and the two packages every option needs:

```bash
apt-get update -qq
apt-get install -y --no-install-recommends xrdp xorgxrdp dbus-x11 fonts-dejavu-core
apt-get install -y --no-install-recommends xfce4 xfce4-terminal   # or your choice
```

## 4. Create a login account

```bash
adduser rdpuser
# log in once with `wsl -d Ubuntu-26.04 -u rdpuser -- true` so the home is made
mkdir -p /home/rdpuser/.ssh   # if you will use SSH instead
```

`xrdp.ini` ships with `username=ask`, so the client is asked for the account and
the password. Keeping `ask` avoids a password in a world-readable config file.

## 5. Point xrdp at the chosen desktop

`/etc/xrdp/startwm.sh` is what an authenticated session executes, so it
decides which desktop appears:

```bash
cat >/etc/xrdp/startwm.sh <<'EOF'
#!/bin/bash
unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR
export XDG_SESSION_TYPE=x11
export XDG_CURRENT_DESKTOP=XFCE
export XDG_SESSION_DESKTOP=XFCE
exec /usr/bin/startxfce4
EOF
chmod +x /etc/xrdp/startwm.sh
```

Substitute the command for your choice: `startlxqt`, `mate-session`,
`startplasma-x11`, or `openbox-session`. The `unset` lines matter: xrdp is not
a systemd session, and a stale bus address is the usual cause of a session that
starts and then dies.

## 6. Move xrdp off 3389

```bash
sed -i 's/^port=3389$/port=3390/' /etc/xrdp/xrdp.ini
sed -i 's/^port=3350$/port=3391/' /etc/xrdp/xrdp.ini
grep -E '^port=' /etc/xrdp/xrdp.ini
```

`xrdp.ini` has one listener per section: `[xrdp1]` is the login screen the
client connects to, and `[Xorg]` is the per-session display server. Both must
move. The TLS material xrdp presents by default is `/etc/xrdp/cert.pem` with
`/etc/xrdp/key.pem`; RDP does not chain-validate it, exactly like the
self-signed certificate a Windows host presents.

## 7. Start it and keep it started

```bash
systemctl enable xrdp xrdp-sesman xrdp-xorgxrdp
systemctl restart xrdp-sesman xrdp-xorgxrdp xrdp
systemctl --no-pager --lines=0 status xrdp
ss -ltn | grep 3390
```

## 8. Keep the VM alive

**This is the single most common reason the lab appears to be down.** WSL stops
the virtual machine when no distribution session is running, and xrdp dies with
it; `mstsc` then reports error `0x204` and `Test-NetConnection` returns
`False`. Hold a session open from Windows:

```powershell
wsl -d Ubuntu-26.04 -u root -- sleep infinity
```

For mirrored networking, `localhost` works directly. In the default NAT mode it
does not: connect to the address the distro owns.

```powershell
$ip = (wsl -d Ubuntu-26.04 -u root -- hostname -I).Trim()   # e.g. 172.17.214.245
Test-NetConnection -ComputerName $ip -Port 3390
```

Then connect from the Windows side:

```powershell
mstsc.exe /v:$ip:3390
```

## 9. Verify with the client, not only with mstsc

`mstsc` proves the desktop works. It does not prove the encoder does, so probe
the same server with this repository's own tool:

```powershell
dotnet run --project src/RdpClient.Cli -- --host $ip --port 3390 --tls-only
```

A healthy run reaches TLS and then stops at MCS, because xrdp requires
credentials that this client cannot present yet:

```text
negotiated version 0x00000001, SelectedProtocol 0x00000001
External Security Protocol: TLS
Tls13, subject 'CN=...' (self-signed certificate accepted; ...)
sent MCS Connect Initial (355 bytes)
MCS refused the connection: MCS Connect Response result 3: connection refused
```

`result 3` is the expected end of this stage and not a defect. Anything earlier
in that output is a real finding.

## 10. Read the server's log before theorising

xrdp names the field it was parsing, which turns a guess into a measurement:

```bash
tail -40 /var/log/xrdp.log
tail -40 /var/log/xrdp-sesman.log
journalctl -u xrdp -n 30 --no-pager
```

The message that found the correlation block defect:

```text
[ERROR] Parsing [MS-RDPBCGR] RDP_NEG_CORRELATION_INFO Not enough bytes in the stream: expected 35, remaining 23
```

The Windows equivalent is the `RdpCoreTS/Operational` log described in
[AGENTS.md](../AGENTS.md#ask-the-server-what-it-thinks).

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| mstsc: `0x204`, `Test-NetConnection` false | the VM was stopped when the distro had no session | hold `wsl ... -- sleep infinity` open |
| `No connection could be made ... actively refused` | same as above, seen from `rdpprobe` | same as above |
| `E: Could not get lock /var/lib/apt/lists/lock` | the first-boot `apt upgrade` still running | wait for `apt-get` and `dpkg` to exit |
| `localhost:3390` unreachable from Windows | NAT networking does not forward it | use the distro address, or set `networkingMode=mirrored` in `%UserProfile%\.wslconfig` |
| session starts, then the window closes | stale D-Bus address in the session | `unset DBUS_SESSION_BUS_ADDRESS` in `startwm.sh` |
| `xrdp_sec_incoming: xrdp_iso_incoming failed` | the PDU was refused during negotiation | read the error above it in `/var/log/xrdp.log` |
| everything works, then the VM vanishes | WSL idle shutdown | see step 8 |

## Turning the lab off

```bash
systemctl stop xrdp xrdp-sesman xrdp-xorgxrdp
systemctl disable xrdp xrdp-sesman xrdp-xorgxrdp
```

Or remove the distro entirely with `wsl --unregister Ubuntu-26.04`, which
deletes its filesystem and every file inside it.

## Security notes

xrdp listens on port 3390 of the distro. In NAT mode that address is reachable
from the Windows host and from anything that can route to the VM, so do not
port-forward it. The certificate xrdp presents is self-signed and RDP does not
validate it, which is normal for RDP and is not a signal of a working
authentication path.
