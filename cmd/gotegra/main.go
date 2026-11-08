// Command gotegra drives an NVIDIA Tegra SoC in RCM (recovery) mode over native
// USB (libusb via purego, no cgo) — the USB side of NVIDIA's tegrarcm_v2 for the
// T234 (Orin) path, reimplemented so it runs anywhere libusb does, with no VM.
package main

import (
	"fmt"
	"os"

	"github.com/levitree/gotegra"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "uid":
		err = cmdUID()
	case "flash":
		err = cmdFlash(os.Args[2:])
	case "rcmboot":
		err = cmdRcmBoot(os.Args[2:])
	case "applet":
		err = cmdApplet(os.Args[2:])
	case "mb2probe":
		err = cmdMb2Probe()
	case "flashboot":
		err = cmdFlashBoot(os.Args[2:])
	case "reboot":
		err = cmdReboot(os.Args[2:])
	case "flashwrite":
		err = cmdFlashWrite(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gotegra - native NVIDIA Tegra RCM over libusb (T234/Orin)

usage:
  gotegra uid                read BR_CID and decode the fuse / secure-boot state
  gotegra flash <blob-dir>   full RCM boot in one session: UID, the four bootrom
                             blobs, pollbl, then the applet (resolves standard
                             blob filenames from the directory)
  gotegra rcmboot <blob...>  bulk-OUT the given signed blobs to the bootrom, in order
  gotegra applet <applet>    poll the bootloader, then download the applet
  gotegra mb2probe           query a running mb2/mb2_applet over the 3p protocol
`)
}

func cmdUID() error {
	d, err := gotegra.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	cid, raw, err := d.ReadBRCID()
	if err != nil {
		return err
	}
	fmt.Printf("BR_CID: %s\n", cid)
	fmt.Printf("raw descriptor: %x\n", raw)
	if auth, ok := gotegra.DecodeFuseState(cid); ok {
		fmt.Printf("fuse/secure-boot: %s\n", auth)
	}
	return nil
}

func cmdFlash(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotegra flash <blob-dir>")
	}
	bootBlobs, applet, err := gotegra.ResolveRcmBlobs(args[0])
	if err != nil {
		return err
	}
	d, err := gotegra.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	return d.FullRcmBoot(bootBlobs, applet)
}

func cmdRcmBoot(files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("usage: gotegra rcmboot <blob1> [blob2 ...]")
	}
	d, err := gotegra.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	if cid, _, err := d.ReadBRCID(); err == nil {
		fmt.Printf("BR_CID: %s\n", cid)
	}
	return d.RcmBoot(files)
}

func cmdApplet(files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("usage: gotegra applet <applet.bin.encrypt>")
	}
	d, err := gotegra.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	ver, lastErr, err := d.PollBootloader()
	if err != nil {
		return fmt.Errorf("pollbl: %w", err)
	}
	fmt.Printf("BL: version %q last_boot_error=%d\n", ver, lastErr)
	return d.RcmBoot(files)
}

func cmdMb2Probe() error {
	d, err := gotegra.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Mb2Probe()
}

func cmdFlashBoot(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotegra flashboot <rcmboot-blob-dir>")
	}
	bootBlobs, postBlobs, err := gotegra.ResolveFlashBootBlobs(args[0])
	if err != nil {
		return err
	}
	d, err := gotegra.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	return d.FlashBoot(bootBlobs, postBlobs)
}

func cmdFlashWrite(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: sudo gotegra flashwrite <flashpkg.img> <nvme.img>")
	}
	return gotegra.FlashWrite(args[0], args[1])
}

func cmdReboot(args []string) error {
	mode := "recovery"
	if len(args) > 0 {
		mode = args[0]
	}
	if mode != "recovery" && mode != "coldboot" {
		return fmt.Errorf("usage: gotegra reboot [recovery|coldboot]")
	}
	d, err := gotegra.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	return d.RebootTo(mode == "recovery")
}
