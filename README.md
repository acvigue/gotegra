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
- `flash` / `rcmboot` / `applet` — the full bootrom RCM boot (bulk-OUT the signed
  blobs `bct_br → mb1 → psc_bl1 → bct_mb1`, poll the bootloader, download the
  `applet`). **Working** — boots mb2_applet.
- `mb2probe` / 3p protocol — the mb2/applet command transport
  (`internal` `threeP`). **Implemented, not yet hardware-verified.**

The signed blobs themselves are produced by NVIDIA's offline tools
(`tegraflash`/`tegrabct`/`tegrasign`, which need no USB); gotegra only does the
USB transport.

## Library

```go
d, err := gotegra.Open()          // find 0955:7323 (T234 APX), claim interface 0
defer d.Close()

cid, _, _ := d.ReadBRCID()         // "0x8001..." ; gotegra.DecodeFuseState(cid)
boot, applet, _ := gotegra.ResolveRcmBlobs(dir)
d.FullRcmBoot(boot, applet)        // UID → 4 blobs → pollbl → applet, one session
```

## CLI

```
gotegra uid
gotegra flash <blob-dir>
gotegra rcmboot <blob...>
gotegra applet <applet>
gotegra mb2probe
```

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
  optional `[len][payload][checksum]`, ACK(3)/NACK(4), byte-sum checksum.
