//go:build darwin

package gotegra

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LUN wait budgets. The nvme LUN only appears after QSPI programming and a
// whole-drive blkdiscard have run, and the device then holds it exported
// indefinitely, so a long wait costs nothing while a short one strands a flash
// that was going fine (`gotegra resume` picks such a flash back up).
const (
	flashpkgLUNTimeout = 3 * time.Minute
	nvmeLUNTimeout     = 30 * time.Minute
	statusLUNTimeout   = 15 * time.Minute
	probeLUNTimeout    = 3 * time.Minute

	lunPollInterval   = time.Second
	lunStatusInterval = 15 * time.Second
)

// StatusImagePath is where the device's returned flashpkg (status + logs) is
// captured for inspection.
const StatusImagePath = "/tmp/flashpkg-status.img"

// LUN export names the agent uses (its setup_usb_export inquiry_string).
const (
	lunFlashpkg = "flashpkg"
	lunNvme     = "nvme0n1"
)

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

// lunInfo is what diskutil and IOKit tell us about an external disk.
type lunInfo struct {
	dev     string
	size    int64
	media   string // diskutil "Device / Media Name" (macOS builds it from the inquiry PRODUCT)
	vendor  string // IOKit "Vendor Name" = SCSI inquiry vendor — the agent's export name
	product string // IOKit "Product Name" = inquiry product — the agent puts its serial here
	text    string // whole `diskutil info` output
}

func (li lunInfo) String() string {
	return fmt.Sprintf("%s (vendor %q, product %q, %d MiB)", li.dev, li.vendor, li.product, li.size>>20)
}

// blockDeviceIdentity maps whole disks ("/dev/disk4") to their IOKit
// {vendor, product} inquiry strings, from `ioreg -r -c IOBlockStorageDevice`:
// each storage device prints its "Device Characteristics" line, then its
// IOMedia child carrying the "BSD Name". This is the same vendor field
// NVIDIA's host script matches as udev's ID_VENDOR; diskutil never shows it.
func blockDeviceIdentity() map[string][2]string {
	out, err := exec.Command("ioreg", "-r", "-c", "IOBlockStorageDevice", "-l", "-w0").Output()
	if err != nil {
		return nil
	}
	ids := map[string][2]string{}
	var vendor, product string
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "+-o "):
			// a new top-level storage device: forget the previous identity
			vendor, product = "", ""
		case strings.Contains(line, `"Device Characteristics"`):
			vendor = strings.TrimSpace(ioregStr(line, `"Vendor Name"=`))
			product = strings.TrimSpace(ioregStr(line, `"Product Name"=`))
		case strings.Contains(line, `"BSD Name" = "`):
			if name := ioregStr(line, `"BSD Name" = `); wholeDiskRe.MatchString(name) {
				ids["/dev/"+name] = [2]string{vendor, product}
			}
		}
	}
	return ids
}

var wholeDiskRe = regexp.MustCompile(`^disk[0-9]+$`)

// ioregStr returns the double-quoted string value that follows key in an ioreg
// line ("" when absent).
func ioregStr(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key):]
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func inspectDisk(dev string, ids map[string][2]string) lunInfo {
	li := lunInfo{dev: dev}
	if id, ok := ids[dev]; ok {
		li.vendor, li.product = id[0], id[1]
	}
	out, err := exec.Command("diskutil", "info", dev).Output()
	if err != nil {
		return li
	}
	li.text = string(out)
	for _, line := range strings.Split(li.text, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "Disk Size:") || strings.HasPrefix(l, "Total Size:"):
			if i := strings.Index(l, "("); i >= 0 {
				if f := strings.Fields(l[i+1:]); len(f) > 0 {
					li.size, _ = strconv.ParseInt(f[0], 10, 64)
				}
			}
		case strings.HasPrefix(l, "Device / Media Name:"):
			li.media = strings.TrimSpace(strings.TrimPrefix(l, "Device / Media Name:"))
		}
	}
	return li
}

// name says which of the agent's LUNs this disk is ("flashpkg", "nvme0n1") or
// "" for a disk that is not one of them — a USB SSD that happens to be plugged
// in must never be written to. The agent tags each LUN's SCSI inquiry VENDOR
// with its export name (inquiry_string = "%-8s%-16s" name serial), which IOKit
// exposes as "Vendor Name" (diskutil's media name only carries the product, i.e.
// the serial, so it cannot be used). GOTEGRA_ANY_LUN=1 falls back to
// classifying by size for a gadget whose inquiry string lacks the tag.
func (li lunInfo) name() string {
	switch strings.ToLower(li.vendor) {
	case lunFlashpkg:
		return lunFlashpkg
	case lunNvme:
		return lunNvme
	}
	if os.Getenv("GOTEGRA_ANY_LUN") == "1" {
		if li.size <= 512<<20 {
			return lunFlashpkg
		}
		if li.size > 1<<30 {
			return lunNvme
		}
	}
	return ""
}

// earlyStatusError: the flashpkg LUN appeared while the nvme LUN was expected,
// i.e. the device stopped before export-devices and is reporting back.
type earlyStatusError struct{ li lunInfo }

func (e *earlyStatusError) Error() string {
	return fmt.Sprintf("device re-exported the flashpkg LUN (%s) instead of the nvme LUN", e.li.dev)
}

// waitLUN waits for the agent's LUN named want. While waiting it prints a line
// every lunStatusInterval with the elapsed time and what the USB tree shows of
// the Tegra side, so a stalled device is distinguishable from a slow one. A
// flashpkg LUN showing up while nvme0n1 is wanted is returned with
// *earlyStatusError. Disks that are not the agent's are named once and ignored.
func waitLUN(want string, timeout time.Duration) (lunInfo, error) {
	start := time.Now()
	deadline := start.Add(timeout)
	nextStatus := start.Add(lunStatusInterval)
	ignored := map[string]bool{}
	var progress progressWatcher
	defer progress.close()
	for time.Now().Before(deadline) {
		disks := externalDisks()
		var ids map[string][2]string
		if len(disks) > 0 {
			ids = blockDeviceIdentity()
		}
		for _, dev := range disks {
			li := inspectDisk(dev, ids)
			if li.size == 0 {
				continue
			}
			got := li.name()
			switch {
			case got == want:
				return li, nil
			case got == lunFlashpkg && want == lunNvme:
				return li, &earlyStatusError{li}
			case got == "" && !ignored[dev]:
				ignored[dev] = true
				progress.endLine()
				fmt.Printf("  ignoring %s: not a Tegra flashing LUN (GOTEGRA_ANY_LUN=1 overrides)\n", li)
			}
		}
		// A flashing image with the progress channel says what it is doing;
		// otherwise all we can report is how long it has been quiet.
		if progress.poll() {
			nextStatus = time.Now().Add(lunStatusInterval)
		} else if time.Now().After(nextStatus) {
			fmt.Printf("  still waiting for the %s LUN (%s elapsed; usb: %s)\n",
				want, time.Since(start).Round(time.Second), usbPresence())
			nextStatus = time.Now().Add(lunStatusInterval)
		}
		time.Sleep(lunPollInterval)
	}
	progress.close()
	return lunInfo{}, fmt.Errorf("timed out after %s waiting for the %s LUN (usb: %s)", timeout, want, usbPresence())
}

// waitRCM waits for the bootrom RCM device to (re)appear on USB.
func waitRCM(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.HasPrefix(usbPresence(), "RCM") {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

// usbPresence describes what the USB tree shows of the Tegra side right now:
// the bootrom RCM device (0955:7323), the flashing gadget (1d6b:0104), or
// neither. The agent unbinds the gadget while it works, so "no Tegra device"
// during the nvme wait is normal for a while; after the RCM device reappears
// the box has rebooted into recovery (or been put there) and the run is over.
func usbPresence() string {
	out, err := exec.Command("ioreg", "-p", "IOUSB", "-l", "-w0").Output()
	if err != nil {
		return "ioreg unavailable"
	}
	var rcm, gadget bool
	// ioreg prints one property block per device after its "+-o" header, so
	// a device's idVendor and idProduct live in the same block.
	for _, block := range strings.Split(string(out), "+-o ") {
		v, p := ioregInt(block, `"idVendor" = `), ioregInt(block, `"idProduct" = `)
		switch {
		case v == VendorNVIDIA && p == ProductT234:
			rcm = true
		case v == VendorLinuxFdn && (p == ProductL4TFlash || p == ProductL4TProgress):
			gadget = true
		}
	}
	switch {
	case rcm && gadget:
		return "RCM device AND flashing gadget present"
	case rcm:
		return "RCM device present (box is back in recovery)"
	case gadget:
		return "flashing gadget present"
	}
	return "no Tegra device"
}

func ioregInt(block, key string) int {
	i := strings.Index(block, key)
	if i < 0 {
		return -1
	}
	f := strings.Fields(block[i+len(key):])
	if len(f) == 0 {
		return -1
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return -1
	}
	return n
}

// unmountVolumes unmounts any volume macOS auto-mounted from the disk, without
// ejecting it (the gadget stays configured). Errors are ignored: nothing
// mounted is the normal case.
func unmountVolumes(dev string) {
	_ = exec.Command("diskutil", "unmountDisk", "force", dev).Run()
}

// disconnectLUN tells the flashing agent "host is done with this LUN, go process
// it." The agent's wait_for_disconnect loops until the USB gadget leaves the
// "configured" state — the real host-side initrd-flash does this with
// `udisksctl power-off` (USB power-off) or a sysfs unbind/rebind. On macOS
// `diskutil eject` only ejects the LUN and does NOT deconfigure the gadget (and
// detaches it from libusb's view, so a reset afterwards cannot open it), so we
// leave the disk alone and act on the still-attached gadget directly:
// DisconnectGadget holds SET_CONFIGURATION 0 long enough for the agent's 1 s
// poll to see it. The gadget re-enumerates afterwards as the next LUN.
func disconnectLUN(dev string) {
	for attempt := 1; attempt <= 6; attempt++ {
		if method, err := DisconnectGadget(); err == nil {
			fmt.Printf("  gadget disconnected via %s [try %d]\n", method, attempt)
			return
		} else {
			fmt.Printf("  disconnect try %d: %v\n", attempt, err)
		}
		time.Sleep(700 * time.Millisecond)
	}
	fmt.Println("  !! software disconnect failed — physically unplug and replug the USB-C cable to continue")
}
