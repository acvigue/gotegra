//go:build darwin

package gotegra

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The l4t_initrd_flash mass-storage write stage (macOS). Once the flashing
// kernel is up (see FlashBoot), the device exposes a sequence of USB mass-storage
// LUNs: a ~134 MB "flashpkg" LUN (write the flash package, eject), then the
// "nvme0n1" LUN (write the rootfs image, eject), then "flashpkg" again for the
// final status. We write raw images to the block devices and eject with
// diskutil; the raw writes and ejects need root (run with sudo).

func externalDisks() []string {
	out, err := exec.Command("diskutil", "list", "external", "physical").Output()
	if err != nil {
		return nil
	}
	var ds []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "/dev/disk") {
			ds = append(ds, strings.Fields(line)[0])
		}
	}
	return ds
}

func diskSize(dev string) int64 {
	out, err := exec.Command("diskutil", "info", dev).Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "Disk Size:") || strings.HasPrefix(l, "Total Size:") {
			if i := strings.Index(l, "("); i >= 0 {
				if f := strings.Fields(l[i+1:]); len(f) > 0 {
					n, _ := strconv.ParseInt(f[0], 10, 64)
					return n
				}
			}
		}
	}
	return 0
}

// waitLUN waits for an external disk in the given size class: flashpkg LUNs are
// small (~134 MB), the nvme LUN is multi-GB.
func waitLUN(small bool, timeoutSec int) (string, int64, error) {
	kind := "nvme"
	if small {
		kind = "flashpkg"
	}
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		for _, d := range externalDisks() {
			sz := diskSize(d)
			if sz == 0 {
				continue
			}
			if small && sz <= 512<<20 {
				return d, sz, nil
			}
			if !small && sz > 1<<30 {
				return d, sz, nil
			}
		}
		time.Sleep(time.Second)
	}
	return "", 0, fmt.Errorf("timed out waiting for the %s LUN", kind)
}

func ejectDisk(dev string) error {
	return exec.Command("diskutil", "eject", dev).Run()
}

// writeRawImage streams an image file onto the raw block device (/dev/rdiskN,
// unbuffered and faster). Needs root.
func writeRawImage(imgPath, dev string) error {
	raw := strings.Replace(dev, "/dev/disk", "/dev/rdisk", 1)
	src, err := os.Open(imgPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(raw, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s (needs root — run with sudo): %w", raw, err)
	}
	defer dst.Close()
	buf := make([]byte, 1<<20)
	var written int64
	last := time.Now()
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			written += int64(n)
			if time.Since(last) > 2*time.Second {
				fmt.Printf("\r  wrote %d MiB", written>>20)
				last = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	fmt.Printf("\r  wrote %d MiB (done)\n", written>>20)
	return nil
}

// FlashWrite runs the mass-storage write stage: flashpkg image → flashpkg LUN →
// eject → nvme image → nvme LUN → eject → final status.
func FlashWrite(flashpkgImg, nvmeImg string) error {
	fmt.Println("Waiting for the flashpkg LUN...")
	d1, sz1, err := waitLUN(true, 180)
	if err != nil {
		return err
	}
	fmt.Printf("flashpkg LUN %s (%d MiB): writing flash package\n", d1, sz1>>20)
	if err := writeRawImage(flashpkgImg, d1); err != nil {
		return err
	}
	if err := ejectDisk(d1); err != nil {
		return fmt.Errorf("eject %s: %w", d1, err)
	}

	fmt.Println("Waiting for the nvme LUN (device is flashing the bootloader)...")
	d2, sz2, err := waitLUN(false, 300)
	if err != nil {
		return err
	}
	fmt.Printf("nvme LUN %s (%d MiB): writing rootfs image\n", d2, sz2>>20)
	if err := writeRawImage(nvmeImg, d2); err != nil {
		return err
	}
	if err := ejectDisk(d2); err != nil {
		return fmt.Errorf("eject %s: %w", d2, err)
	}

	fmt.Println("Waiting for the flashpkg LUN (final status)...")
	if d3, _, err := waitLUN(true, 300); err == nil {
		_ = ejectDisk(d3)
		fmt.Println("Flash sequence complete; the device will reboot into the flashed OS.")
	} else {
		fmt.Println("rootfs written; did not see the final-status LUN (the device may have already rebooted).")
	}
	return nil
}
