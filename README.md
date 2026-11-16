# gotegra

Native Go driver for an NVIDIA Tegra SoC in **RCM (recovery) mode**, over USB,
with **no cgo** — libusb-1.0 is bound at runtime with
[purego](https://github.com/ebitengine/purego). It reimplements the USB side of
NVIDIA's `tegrarcm_v2` for the **T234 (Orin)** path, so recovery/flash USB works
anywhere libusb does (macOS/Linux/Windows) with no x86 VM.

This exists because NVIDIA's flashing stack is a Linux x86 binary that drives the
device through Linux `usbdevfs` ioctls; the only way to run it on an Apple-Silicon
Mac is a QEMU x86 guest whose emulated USB passthrough can't complete the RCM
bulk-OUT transfers. Doing the USB natively here sidesteps that entirely.

## Status

- `uid` — read `BR_CID` (USB string descriptor #3) and decode the fuse /
  secure-boot state. **Working.**
- `applet-boot` / `rcmboot` / `applet` — the full bootrom RCM boot (bulk-OUT the
  signed blobs `bct_br → mb1 → psc_bl1 → bct_mb1`, poll the bootloader, download
  the `applet`). **Working** — boots mb2_applet.
- `flashall` / `flashqspi` / `probe-nvme` / `resume` / `status` / `run-pkg` — the
  T234 initrd-flash flow: RCM-boot the flashing kernel (`mem_rcm` + `blob.bin`),
  then drive the agent's USB mass-storage LUNs (`flashpkg` → `nvme0n1` →
  `flashpkg` status). **Working end to end on macOS** (full QSPI + NVMe flash of
  a Jetson Orin NX confirmed). macOS-only for now.
- `mb2probe` / `reboot` — the mb2/applet 3p command transport.
  **Implemented, not yet hardware-verified.**
- `burnfuses` (alias `fuse`) — FSKP fuse burning for T234/Orin. Builds the FSKP
  RCM session (bootrom blobs → pollbl → mem BCT + `blob.bin`) that boots the
  signed FSKP MB2, which burns the fuses; or, with `-via-applet`, sends
  `--oem burnfuses` to a running mb2_applet over the 3p protocol. **Dry run by
  default; the real burn is gated behind `-burn` and never run against hardware
  here. IRREVERSIBLE.** Transport reversed from `tegrarcm_v2`; the FSKP path
  reuses the (unverified) `flashboot` transport.

The signed blobs themselves are produced by NVIDIA's offline tools
(`tegraflash`/`tegrabct`/`tegrasign`, which need no USB); gotegra only does the
USB transport. Fuse blobs are likewise built and signed offline (odmfuse via
`tegraparser` + `tegrasign_v3`); gotegra never signs or assembles them. The
flashing inputs are a *flashpack* (`rcmboot/` RCM blobs, `flashpkg.img` ext4
command package, `flashparts/` with `flash.idx` + partition images + the
rootfs), as produced by luka-firmware's `ci/flashpack.sh`.

The signed RCM blobs come in two spellings, and a unit takes one of them:
`*.encrypt` is signed with the zero key, for an unfused (NS) unit; `*.signed` is
signed with a PKC key, for a unit whose `PublicKeyHash` fuse holds that key's
hash. gotegra takes whichever the directory holds, and

- refuses a directory that holds both (two builds copied into one place: sent
  by name, the set would be a mix no unit boots);
- reads `BR_CID` before the first download and refuses to send PKC-signed blobs
  to an unfused unit, or zero-key blobs to a fused one. Every command that
  RCM-boots from a blob directory does this (`flashall`, `flashqspi`,
  `probe-nvme`, `run-pkg`, `flashboot`, `applet-boot`, `burnfuses`); `rcmboot`
  and `applet` send exactly the files they are given. NVIDIA's flasher draws the
  same line.

Resolving PKC-signed blobs is tested on the file names of a real PKC flashpack;
**sending them to a fused unit is not hardware-verified** (no fused unit yet).

### Flashing flow (what the device-side agent does)

The agent is the initramfs `/init` inside `blob.bin` (meta-tegra initrd-flash).
It exports USB mass-storage LUNs on gadget `1d6b:0104`, each tagged in its SCSI
inquiry vendor field with its name, and between LUNs waits for the host to
*disconnect* (UDC state leaves `configured`):

1. `flashpkg` (128 MiB ext4): host writes `flashpkg/conf/command_sequence`,
   `flashpkg/bootloader/*` and an empty `flashpkg/logs/`. Must be written
   **full** (not sparse) and be ext4.
2. Agent runs the sequence, e.g. `export-devices nvme0n1`, `bootloader` (erase +
   program the QSPI), `reboot`.
3. `nvme0n1`: host writes each partition at its `flash.idx` offset. Small images
   are written in full; the rootfs is written sparsely with its ext4 metadata
   forced, so no pre-erased drive is needed. gotegra disconnects with
   `DisconnectGadget` (SET_CONFIGURATION 0 held ~2.5 s; `diskutil eject` does
   not deconfigure the gadget).
4. `flashpkg` again with `flashpkg/status` + `flashpkg/logs/*`; gotegra captures
   it to `/tmp/flashpkg-status.img`, prints it (needs `7z`), releases it so the
   device reboots, and **exits non-zero unless the status is SUCCESS**.

While it waits for a LUN, gotegra also watches for the agent's optional progress
gadget (`1d6b:0105` "L4T flash progress", a CDC-ACM port a flashing image may
bind between LUNs; see `progress.go` for the line format) and shows what the
device reports, e.g. `device: programming QSPI 37/115 (32%) A_mb2`. Without it
the wait shows a "still waiting" line every 15 s. **Not yet verified on
hardware.**

Everything that can fail on the host is checked before the device is touched:

- the RCM blobs resolve;
- the package lints clean (`pkg-show` runs the same checks): command sequence,
  `logs/`, the QSPI inputs, and an MB1 cold-boot BCT that actually carries the
  `A_MEM_BCT` / `A_mb2` locations — one without them programs a QSPI that
  leaves RCM and never reaches UEFI;
- every image `flash.idx` names exists and fits its partition.

Failure path: if the agent cannot export the NVMe it comes back with the
**status LUN instead of the nvme LUN**. gotegra treats that as NVIDIA's host
does ("got flashpkg when expecting nvme0n1"), prints the logs, and exits.
`probe-nvme` exercises just the export (no QSPI, nothing written) to check a
flashing environment without touching the drive.

## Library

```go
d, err := gotegra.Open()          // find 0955:7323 (T234 APX), claim interface 0
defer d.Close()

cid, _, _ := d.ReadBRCID()         // "0x8001..." ; gotegra.DecodeFuseState(cid)
boot, applet, _ := gotegra.ResolveRcmBlobs(dir)
d.FullRcmBoot(boot, applet)        // UID → 4 blobs → pollbl → applet, one session
```

## CLI

`gotegra` lists the commands; `gotegra help <command>` shows one.

```
sudo gotegra flashall  <flashpack-dir>             # RCM boot, QSPI, NVMe, status
sudo gotegra flashqspi <flashpack-dir>             # QSPI only, NVMe untouched
sudo gotegra probe-nvme <flashpack-dir>            # non-destructive NVMe check
sudo gotegra resume <parts-dir>                    # continue from the nvme stage
sudo gotegra status                                # read + release the status LUN

gotegra pkg-show <flashpkg.img>                    # sequence + lint, no device
gotegra pkg-seq  <in.img> <out.img> 'verb;verb'    # new command sequence
gotegra pkg-drop <in.img> <out.img> <verb>...      # remove verbs

gotegra uid | flashboot | applet-boot | rcmboot | applet | mb2probe | reboot

gotegra burnfuses <blob-dir>           # dry run (FSKP); -burn to burn (IRREVERSIBLE)
gotegra burnfuses -via-applet <blob>   # --oem burnfuses over 3p to a running applet
```

A flashpack directory holds `rcmboot/`, `flashpkg.img` and `flashparts/`; the
commands that take one also accept the pieces separately
(`flashall <rcmboot-dir> <flashpkg.img> <parts-dir>`), which lets known-good RCM
blobs boot the agent for a new package.

LUNs are matched by the agent's SCSI inquiry vendor (`flashpkg` / `nvme0n1`,
read from IOKit), never by "whatever external disk is there";
`GOTEGRA_ANY_LUN=1` falls back to size classes. The nvme wait is 30 min, with a
status line every 15 s showing what the USB tree sees.

## Protocol notes (reversed from tegrarcm_v2, T234/mainT23x)

- `--uid` is a control transfer: `GET_DESCRIPTOR(string, index 3)` — the bootrom
  exposes BR_CID as USB string descriptor #3.
- Fuse state is in `BR_CID` dword0: bit 31 = production, bits [27:24] select the
  mode (`0` = NS/unfused, `1-5` = PKC, `9-d` = SBKPKC).
- `--download` is a raw bulk-OUT of each signed blob on EP `0x01`, in order; no
  RCM framing and no per-blob status (NVIDIA's `RcmDownLoadImages`).
- `--pollbl` is a 0x44-byte bulk-IN on EP `0x81` (bootloader version +
  last_boot_error); the applet must follow promptly or MB1 boots the on-flash OS.
- The mb2 "3p" protocol: 16-byte header `[magic=3][type][seq_lo][seq_hi]`,
  optional `[len][payload][checksum]`, ACK(3)/NACK(4), byte-sum checksum. A 3p
  *command* is a type-1 packet whose payload is `[opcode u32][command struct]`;
  the opcode is the RCM command (`NvTegra3pCommandSend`): 2 = download,
  6 = OEM command, 9 = command-complete, 10 = boot.
- **Fuse burning (FSKP, T234/Orin).** gotegra is only the RCM transport; the
  fuse values live in a fuse XML (`fuse_t234.xml`, `MagicId=0x45535546` = "FUSE"),
  are compiled to a fuse blob by `tegraparser --fuse_info`, concatenated into
  `fskp_t234.bin` (`tegraparser --fskp_info`), and encrypted+signed offline by
  `tegrasign_v3` (AES-GCM under `FSKP_EK`, then HMAC-SHA256 under `FSKP_AK` —
  `tegraflash_oem_sign_fskp`). gotegra never builds or signs the blob. Two
  transports, both reversed from `tegrarcm_v2`:
  - **FSKP-as-MB2 (the T234 `tegraflash burnfuses` path, production).** The signed
    FSKP MB2 is packed into `blob.bin`, and the RCM sequence is identical to a
    flash boot: bootrom blobs (raw bulk-OUT) → `pollbl` → `--download bct_mem`
    (mem BCT) → `--download blob` (blob.bin), all raw bulk-OUT. Post-`pollbl`
    `--download` to MB1 is raw bulk-OUT, not 3p (`NvTegraAppletHandleDownload`
    falls back to the bootloader download when no applet is running). MB1 then
    runs the FSKP MB2, which burns the fuses. This reuses `flashboot`.
  - **Applet `--oem burnfuses` (generic path).** To a running `mb2_applet`: a
    type-1 command packet `[6][6,0,0,0]` (opcode 6 = OEM, OEM cmd 6 = burnfuses),
    then the signed fuse blob as one type-2 data packet, then a status packet
    (opcode 8; status u64 `0` = success) — `NvTegraRunOemCmd`. Not used by T234
    `tegraflash burnfuses`; provided for applet-based fusing.
