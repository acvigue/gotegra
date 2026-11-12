//go:build darwin

package gotegra

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The l4t_initrd_flash mass-storage write stage (macOS). Once the flashing
// kernel is up (see FlashBoot) the device-side agent — the initramfs /init that
// meta-tegra's initrd-flash puts in blob.bin — exposes a sequence of USB
// mass-storage LUNs on the 1d6b:0104 gadget, each tagged in its SCSI inquiry
// vendor field with its export name:
//
//	"flashpkg"  a 128 MiB ext4 the host fills with conf/command_sequence and
//	            bootloader/ (QSPI images + partitions.conf + boot_device_type)
//	"nvme0n1"   the raw NVMe, exported only after the agent has run the
//	            commands before export-devices: `bootloader` (erase + program
//	            the QSPI, backgrounded) and `erase-nvme` (blkdiscard of the
//	            whole drive); the host writes every partition at its flash.idx
//	            offset
//	"flashpkg"  again at the end, carrying flashpkg/status and flashpkg/logs/*
//
// Between LUNs the agent waits for the host to DISCONNECT (its UDC state leaves
// "configured"), which on macOS we trigger with DisconnectGadget. NVIDIA's host
// script identifies each LUN by that vendor string and never times out; it also
// treats "got flashpkg when expecting nvme0n1" as the device reporting an early
// final status, because the agent's failure path (no /dev/nvme0n1: erase-nvme
// skipped, export-devices gives up after 15 s) ends with the status LUN once the
// QSPI programming has finished. We mirror both. Raw /dev/rdiskN writes and the
// disconnect need root (run with sudo).

// FlashOptions tunes the mass-storage stages.
type FlashOptions struct {
	// NoErase drops the package's `erase-nvme` verb before use, so the agent
	// skips the whole-drive blkdiscard — NVIDIA's own default. Safe because the
	// rootfs write forces the ext4 metadata that would otherwise rely on a
	// zeroed drive. A package without the verb is used as it is.
	NoErase bool
}

// RunPkgOptions tunes RunPkg.
type RunPkgOptions struct {
	PartsDir   string        // write these flash.idx partitions if the nvme LUN appears (else release it unwritten)
	RootfsName string        // rootfs image in PartsDir (default luka-image.ext4)
	NvmeWait   time.Duration // how long to wait for the nvme LUN (default 30 min)
	RCMWait    time.Duration // how long to wait for the RCM device before starting (default 2 min)
}

// flashRun is one pass through the device-side agent. Every public entry point
// is a flashRun with some stages left out.
type flashRun struct {
	rcmbootDir string        // RCM-boot the agent from these blobs ("" = it is already running)
	rcmWait    time.Duration // wait this long for the RCM device (0 = it must be there now)
	pkg        string        // flash package to deliver ("" = resume: already delivered)
	partsDir   string        // flash.idx + images for the nvme LUN ("" = release it unwritten)
	rootfsName string
	nvmeWait   time.Duration // default nvmeLUNTimeout
}

// run does everything that can fail on the host (blob resolution, package lint,
// flash.idx and its images) before the device is touched, so a host-side
// mistake never leaves the box sitting in the agent. It then follows the
// package's command sequence: the nvme LUN if the sequence exports one, the
// final status LUN, and the return to RCM after `reboot forced-recovery`. A
// device status other than SUCCESS is an error.
func (r flashRun) run() error {
	var boot, post []string
	var err error
	if r.rcmbootDir != "" {
		if boot, post, err = ResolveFlashBootBlobs(r.rcmbootDir); err != nil {
			return fmt.Errorf("resolve rcmboot blobs: %w", err)
		}
	}
	// A resumed run has no package to read: the nvme stage is what is left.
	seq := SequenceInfo{ExportsNvme: true, Reboots: true}
	if r.pkg != "" {
		if err := lintOrFail(r.pkg); err != nil {
			return err
		}
		text, err := ReadFlashpkgSequence(r.pkg)
		if err != nil {
			return err
		}
		seq = ParseSequence(text)
		fmt.Printf("flash package %s, command sequence:\n%s", filepath.Base(r.pkg), tailLines(text, 10))
	}
	var parts []idxPart
	if r.partsDir != "" {
		if !seq.ExportsNvme {
			return fmt.Errorf("a parts directory was given but the package never exports the nvme LUN")
		}
		if parts, err = loadParts(r.partsDir, &r.rootfsName); err != nil {
			return err
		}
	}
	if r.nvmeWait == 0 {
		r.nvmeWait = nvmeLUNTimeout
	}

	if r.rcmbootDir != "" {
		d, err := OpenWait(r.rcmWait)
		if err != nil {
			return err
		}
		err = d.FlashBoot(boot, post)
		d.Close()
		if err != nil {
			return fmt.Errorf("flashboot: %w", err)
		}
	}
	if r.pkg != "" {
		if err := stageFlashpkg(r.pkg); err != nil {
			return err
		}
	}
	if seq.ExportsNvme {
		li, err := waitNvmeLUN(r.nvmeWait, seq.ErasesNvme)
		if err != nil {
			return err
		}
		if parts != nil {
			if err := stageNvmeParts(li, parts, r.partsDir, r.rootfsName); err != nil {
				return err
			}
		} else {
			fmt.Printf("nvme LUN %s is exported: the flashing kernel sees the NVMe. Releasing it unwritten.\n", li)
			disconnectLUN(li.dev)
		}
	}
	if err := stageFinalStatus(seq.Bootloader); err != nil {
		return err
	}
	if seq.ForcedRecovery {
		fmt.Println("Sequence ends with `reboot forced-recovery`: waiting for the box to come back in RCM...")
		if !waitRCM(2 * time.Minute) {
			return fmt.Errorf("the RCM device did not reappear within 2 min (usb: %s)", usbPresence())
		}
		fmt.Println("Box is back in recovery mode (0955:7323): ready for the next run.")
	}
	return nil
}

// FlashAllWith runs the entire flash on a device in bootrom RCM: RCM-boot the
// flashing kernel, deliver the package, write every flash.idx partition to the
// NVMe, and check the device's final status. Run with sudo.
func FlashAllWith(rcmbootDir, flashpkgImg, partsDir, rootfsName string, o FlashOptions) error {
	pkg, cleanup, err := prepareFlashpkg(flashpkgImg, o)
	if err != nil {
		return err
	}
	defer cleanup()
	return flashRun{rcmbootDir: rcmbootDir, pkg: pkg, partsDir: partsDir, rootfsName: rootfsName}.run()
}

// FlashWritePartsWith is FlashAllWith for an agent that is already booted
// (`gotegra flashboot`): the mass-storage stages only.
func FlashWritePartsWith(flashpkgImg, partsDir, rootfsName string, o FlashOptions) error {
	pkg, cleanup, err := prepareFlashpkg(flashpkgImg, o)
	if err != nil {
		return err
	}
	defer cleanup()
	return flashRun{pkg: pkg, partsDir: partsDir, rootfsName: rootfsName}.run()
}

// FlashResumeParts continues a flash from the nvme stage: for when an earlier
// run delivered the package but stopped before the nvme LUN appeared. The
// device keeps that LUN exported until the host releases it, so the partition
// writes and the final-status handshake can be picked up any time later.
func FlashResumeParts(partsDir, rootfsName string) error {
	return flashRun{partsDir: partsDir, rootfsName: rootfsName}.run()
}

// qspiDropVerbs are the commands that touch storage other than the boot flash.
var qspiDropVerbs = []string{"export-devices", "erase-nvme", "erase-mmc", "extra", "extra-pre-wipe"}

// FlashQspi programs only the QSPI boot flash and checks the device's result,
// without touching the NVMe. Any flash package works: one whose sequence also
// exports or erases other storage is first reduced to its `bootloader` and
// `reboot` steps. Run with sudo.
func FlashQspi(rcmbootDir, flashpkgImg string) error {
	if err := lintOrFail(flashpkgImg); err != nil {
		return err
	}
	text, err := ReadFlashpkgSequence(flashpkgImg)
	if err != nil {
		return err
	}
	seq := ParseSequence(text)
	if !seq.Bootloader {
		return fmt.Errorf("%s has no `bootloader` step: nothing would be programmed", filepath.Base(flashpkgImg))
	}
	pkg := flashpkgImg
	if seq.ExportsNvme || seq.ErasesNvme {
		pkg = tempImage("qspi")
		defer os.Remove(pkg)
		if _, err := RewriteFlashpkg(flashpkgImg, pkg, qspiDropVerbs...); err != nil {
			return fmt.Errorf("reduce %s to a QSPI-only package: %w", flashpkgImg, err)
		}
		fmt.Println("package reduced to its QSPI steps (NVMe export/erase dropped)")
	}
	return flashRun{rcmbootDir: rcmbootDir, pkg: pkg}.run()
}

// ProbeNvme is a non-destructive check of the flashing environment: RCM-boot
// the agent with a package whose only commands are "export-devices nvme0n1"
// and "reboot", then report whether the nvme LUN appears — and if not, the
// agent's own logs saying why. With flashpkgImg given, the probe is derived
// from it (its bootloader/ payload stays in the image, unused), so it also
// exercises mounting the real package. Nothing is written to the drive. Run
// with sudo.
func ProbeNvme(rcmbootDir, flashpkgImg string) error {
	pkg := tempImage("probe")
	defer os.Remove(pkg)
	if flashpkgImg != "" {
		if _, err := RewriteFlashpkg(flashpkgImg, pkg, "bootloader", "erase-nvme", "erase-mmc", "extra", "extra-pre-wipe"); err != nil {
			return fmt.Errorf("derive probe package from %s: %w", flashpkgImg, err)
		}
	} else if err := buildFlashpkg(pkg, "export-devices nvme0n1\nreboot\n"); err != nil {
		return fmt.Errorf("build probe flashpkg: %w", err)
	}
	return flashRun{rcmbootDir: rcmbootDir, pkg: pkg, nvmeWait: probeLUNTimeout}.run()
}

// RunPkg runs a hand-built or rewritten flash package exactly as it is: wait
// for the RCM device, RCM-boot the agent, deliver the package and follow its
// command sequence (see flashRun.run). Run with sudo.
func RunPkg(rcmbootDir, flashpkgImg string, o RunPkgOptions) error {
	if o.RCMWait == 0 {
		o.RCMWait = 2 * time.Minute
	}
	return flashRun{rcmbootDir: rcmbootDir, rcmWait: o.RCMWait, pkg: flashpkgImg,
		partsDir: o.PartsDir, rootfsName: o.RootfsName, nvmeWait: o.NvmeWait}.run()
}

// FlashWrite runs the mass-storage stages with one monolithic nvme image
// instead of a flash.idx directory (agent already booted).
func FlashWrite(flashpkgImg, nvmeImg string) error {
	if err := lintOrFail(flashpkgImg); err != nil {
		return err
	}
	if err := stageFlashpkg(flashpkgImg); err != nil {
		return err
	}
	li, err := waitNvmeLUN(nvmeLUNTimeout, true)
	if err != nil {
		return err
	}
	fmt.Printf("nvme LUN %s: writing the disk image\n", li)
	if err := writeRawImage(nvmeImg, li.dev, 0, true, nil); err != nil {
		return err
	}
	disconnectLUN(li.dev)
	return stageFinalStatus(true)
}

// CaptureStatus waits for the device's status LUN, prints its status and logs,
// and releases it (the device then reboots). For a run that ended with the
// device reporting back after the host had given up. A run interrupted
// mid-write leaves the nvme LUN exported, and the agent only moves on to its
// status report once the host lets go of it, so that LUN is released first.
func CaptureStatus() error {
	ids := blockDeviceIdentity()
	for _, dev := range externalDisks() {
		if li := inspectDisk(dev, ids); li.name() == lunNvme {
			fmt.Printf("releasing the still-exported nvme LUN %s (nothing more is written to it)\n", li)
			disconnectLUN(li.dev)
			break
		}
	}
	return stageFinalStatus(true)
}

// prepareFlashpkg applies FlashOptions to the flash package and returns the
// path to use plus a cleanup func.
func prepareFlashpkg(flashpkgImg string, o FlashOptions) (string, func(), error) {
	if err := lintOrFail(flashpkgImg); err != nil {
		return "", nil, err
	}
	if !o.NoErase {
		return flashpkgImg, func() {}, nil
	}
	text, err := ReadFlashpkgSequence(flashpkgImg)
	if err != nil {
		return "", nil, err
	}
	if !ParseSequence(text).ErasesNvme {
		return flashpkgImg, func() {}, nil
	}
	tmp := tempImage("noerase")
	if _, err := RewriteFlashpkg(flashpkgImg, tmp, "erase-nvme"); err != nil {
		return "", nil, fmt.Errorf("rewrite flashpkg without erase-nvme: %w", err)
	}
	return tmp, func() { os.Remove(tmp) }, nil
}

func tempImage(kind string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("gotegra-%s-%d.img", kind, os.Getpid()))
}

// lintOrFail refuses a package the agent cannot act on, before the device is
// touched (a bad package found after the RCM boot strands the box in the agent).
func lintOrFail(img string) error {
	problems, err := LintFlashpkg(img)
	if err != nil {
		return fmt.Errorf("cannot check flash package %s: %w", filepath.Base(img), err)
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("flash package %s would not work on the device:\n  - %s",
		filepath.Base(img), strings.Join(problems, "\n  - "))
}

// stageFlashpkg writes the flash package to the flashpkg LUN and releases it,
// which makes the agent mount it and start the command sequence.
func stageFlashpkg(flashpkgImg string) error {
	fmt.Println("Waiting for the flashpkg LUN...")
	li, err := waitLUN(lunFlashpkg, flashpkgLUNTimeout)
	if err != nil {
		return err
	}
	fmt.Printf("flashpkg LUN %s: writing flash package\n", li)
	if err := writeRawImage(flashpkgImg, li.dev, 0, false, nil); err != nil {
		return err
	}
	disconnectLUN(li.dev)
	return nil
}

// waitNvmeLUN waits for the nvme LUN. If the device reports back early instead
// (the flashpkg LUN again), it captures and prints that report, releases the
// LUN so the device reboots, and returns an error.
func waitNvmeLUN(timeout time.Duration, erase bool) (lunInfo, error) {
	if erase {
		fmt.Println("Waiting for the nvme LUN (the device erases the whole drive first; this can take several minutes)...")
	} else {
		fmt.Println("Waiting for the nvme LUN...")
	}
	li, err := waitLUN(lunNvme, timeout)
	var early *earlyStatusError
	if errors.As(err, &early) {
		fmt.Println("The device re-exported the flashpkg LUN instead of the nvme LUN: it stopped before export-devices and is reporting back.")
		captureStatus(early.li)
		disconnectLUN(early.li.dev)
		return lunInfo{}, fmt.Errorf("device reported a failure before the nvme stage (details above, image at %s); it is rebooting — put it back in recovery to retry", StatusImagePath)
	}
	if err != nil {
		return lunInfo{}, fmt.Errorf("%w\n  if the nvme LUN shows up later, `sudo gotegra resume <parts-dir>` continues from here; if the box never comes back, put it in recovery and run `probe-nvme` first", err)
	}
	return li, nil
}

// stageNvmeParts writes every flash.idx partition at its offset on the nvme LUN
// and releases the LUN. The rootfs (APP/APP_b) is written sparsely with its
// ext4 metadata forced (Ext4MetadataRanges), so it needs no pre-erased drive;
// the other images (GPTs, boot.img, dtb, esp) are small and written in full,
// which is exactly what bmaptool does for a fully mapped file.
func stageNvmeParts(li lunInfo, parts []idxPart, partsDir, rootfsName string) error {
	fmt.Printf("nvme LUN %s: writing partitions by offset\n", li)
	var rootfsForced []byteRange
	rootfsChecked := false
	for _, p := range parts {
		img := p.image(partsDir, rootfsName)
		if img == "" {
			continue // empty partition (reserved/recovery): nothing to write
		}
		fmt.Printf("  %-18s @ %-13d <- %s\n", p.name, p.start, filepath.Base(img))
		// Once the GPT lands, macOS re-reads the partition table and auto-mounts
		// anything it recognizes (the FAT esp) while we are still writing the raw
		// disk underneath it. Keep the volumes unmounted (this does not touch the
		// gadget's USB configuration, so the agent's disconnect wait is unaffected).
		unmountVolumes(li.dev)
		if !p.isRootfs() {
			if err := writeRawImage(img, li.dev, p.start, false, nil); err != nil {
				return fmt.Errorf("write %s: %w", p.name, err)
			}
			continue
		}
		if !rootfsChecked {
			rootfsChecked = true
			rs, err := Ext4MetadataRanges(img)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Base(img), err)
			}
			if rs == nil {
				fmt.Printf("  !! %s is not an ext4 image: sparse write without metadata zero-fill (stale bytes may remain where the image is zero)\n", filepath.Base(img))
			} else {
				fmt.Printf("  ext4: %d metadata extents, %d MiB written even where zero (inode tables, bitmaps, GDT copies)\n",
					len(rs), (&rangeSet{rs: rs}).total()>>20)
			}
			rootfsForced = rs
		}
		if err := writeRawImage(img, li.dev, p.start, true, rootfsForced); err != nil {
			return fmt.Errorf("write %s: %w", p.name, err)
		}
	}
	disconnectLUN(li.dev)
	return nil
}

// stageFinalStatus waits for the agent's final flashpkg LUN, prints its status
// and logs, and releases it so the device reboots. It returns an error unless
// the device reported SUCCESS. qspi says the sequence programs the boot flash,
// which the agent finishes before it reports.
func stageFinalStatus(qspi bool) error {
	if qspi {
		fmt.Println("Waiting for the status LUN (the device finishes programming the QSPI first)...")
	} else {
		fmt.Println("Waiting for the status LUN...")
	}
	li, err := waitLUN(lunFlashpkg, statusLUNTimeout)
	if err != nil {
		return fmt.Errorf("no final status from the device, so the result is unknown: %w", err)
	}
	status, read := captureStatus(li)
	disconnectLUN(li.dev)
	switch {
	case !read:
		fmt.Println("Released; the device is rebooting. Its status could not be read here (see above).")
		return nil
	case strings.HasPrefix(status, "SUCCESS"):
		fmt.Println("Device reported SUCCESS; it is rebooting.")
		return nil
	}
	return fmt.Errorf("device reported %q (logs above, image at %s); it is rebooting", status, StatusImagePath)
}

// captureStatus copies the device's returned flashpkg LUN to StatusImagePath
// and prints flashpkg/status plus the agent's logs from it (the same files
// NVIDIA's host script saves as device-logs-<stamp>/). read is false when the
// status could not be extracted.
func captureStatus(li lunInfo) (status string, read bool) {
	fmt.Printf("status LUN %s: capturing to %s\n", li, StatusImagePath)
	if err := readRawImage(li.dev, StatusImagePath, FlashpkgSize); err != nil {
		fmt.Printf("  (status capture failed: %v)\n", err)
		return "", false
	}
	return showStatusImage(StatusImagePath)
}

// showStatusImage extracts flashpkg/status and flashpkg/logs/* from a captured
// flashpkg ext4 with 7z and prints them.
func showStatusImage(img string) (status string, read bool) {
	sevenZ, err := exec.LookPath("7z")
	if err != nil {
		fmt.Printf("  saved %s — read it with `7z x %s flashpkg/status flashpkg/logs` (brew install p7zip)\n", img, img)
		return "", false
	}
	dir, err := os.MkdirTemp("", "gotegra-status-")
	if err != nil {
		fmt.Printf("  saved %s (could not make a temp dir to read it: %v)\n", img, err)
		return "", false
	}
	defer os.RemoveAll(dir)
	cmd := exec.Command(sevenZ, "x", "-y", "-o"+dir, img, "-x!flashpkg/bootloader", "-x!lost+found")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("  saved %s (7z could not read it: %v)\n%s", img, err, out)
		return "", false
	}
	st, err := os.ReadFile(filepath.Join(dir, "flashpkg", "status"))
	if err != nil {
		fmt.Printf("  device status: (no flashpkg/status in the image)\n")
	} else {
		status, read = strings.TrimSpace(string(st)), true
		fmt.Printf("  device status: %s\n", status)
	}
	logs, _ := filepath.Glob(filepath.Join(dir, "flashpkg", "logs", "*"))
	for _, l := range logs {
		data, err := os.ReadFile(l)
		if err != nil {
			continue
		}
		fmt.Printf("  --- %s (%d bytes) ---\n", filepath.Base(l), len(data))
		fmt.Print(tailLines(string(data), 30))
	}
	fmt.Printf("  (full image kept at %s)\n", img)
	return status, read
}

func tailLines(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = append([]string{fmt.Sprintf("  [... %d earlier lines]", len(lines)-n)}, lines[len(lines)-n:]...)
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString("    ")
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

// idxPart is one partition from a tegra flash.idx line:
// "partnum, dev:inst:name, start_bytes, size, partfile, filesize, attrs, sha".
type idxPart struct {
	name  string
	start int64
	size  int64
	file  string
}

// isRootfs: APP and APP_b both take the one rootfs image, whatever the idx names.
func (p idxPart) isRootfs() bool { return p.name == "APP" || p.name == "APP_b" }

// image is the file written to the partition ("" = nothing is written).
func (p idxPart) image(partsDir, rootfsName string) string {
	switch {
	case p.isRootfs():
		return filepath.Join(partsDir, rootfsName)
	case p.file != "":
		return filepath.Join(partsDir, p.file)
	}
	return ""
}

func parseFlashIdx(path string) ([]idxPart, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var parts []idxPart
	for n, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 5 {
			continue
		}
		loc := strings.Split(strings.TrimSpace(f[1]), ":")
		if len(loc) < 3 {
			return nil, fmt.Errorf("line %d: no dev:inst:name in %q", n+1, strings.TrimSpace(f[1]))
		}
		start, err := strconv.ParseInt(strings.TrimSpace(f[2]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): bad start offset %q", n+1, loc[2], strings.TrimSpace(f[2]))
		}
		size, _ := strconv.ParseInt(strings.TrimSpace(f[3]), 10, 64)
		parts = append(parts, idxPart{name: strings.TrimSpace(loc[2]), start: start, size: size, file: strings.TrimSpace(f[4])})
	}
	return parts, nil
}

// loadParts reads <partsDir>/flash.idx and checks that every image it will
// write is there and fits its partition, so that a missing or oversized file
// stops the run before the device is touched instead of producing a "finished"
// flash with a partition left out.
func loadParts(partsDir string, rootfsName *string) ([]idxPart, error) {
	if *rootfsName == "" {
		*rootfsName = "luka-image.ext4"
	}
	parts, err := parseFlashIdx(filepath.Join(partsDir, "flash.idx"))
	if err != nil {
		return nil, fmt.Errorf("flash.idx: %w", err)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("%s lists no partitions", filepath.Join(partsDir, "flash.idx"))
	}
	var problems []string
	for _, p := range parts {
		img := p.image(partsDir, *rootfsName)
		if img == "" {
			continue
		}
		st, err := os.Stat(img)
		switch {
		case err != nil && p.isRootfs():
			hint := ""
			if _, e := os.Stat(img + ".tar.zst"); e == nil {
				hint = fmt.Sprintf(" (extract it: tar --zstd -xSf %s -C %s)", img+".tar.zst", partsDir)
			}
			problems = append(problems, fmt.Sprintf("%s: rootfs image %s is missing%s", p.name, filepath.Base(img), hint))
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %s is missing", p.name, filepath.Base(img)))
		case p.size > 0 && st.Size() > p.size:
			problems = append(problems, fmt.Sprintf("%s: %s is %d bytes, larger than the %d-byte partition", p.name, filepath.Base(img), st.Size(), p.size))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s cannot be flashed:\n  - %s", partsDir, strings.Join(problems, "\n  - "))
	}
	return parts, nil
}
