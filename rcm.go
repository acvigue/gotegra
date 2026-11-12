package gotegra

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DecodeFuseState decodes the fuse / secure-boot state from a BR_CID string
// ("0x" + 32 hex chars), matching NVIDIA's tegra-flash-helper.sh chip-0x23
// branch. The state lives in dword0: bit 31 = production, bits [27:24] select
// the mode. Returns a human string and whether it was recognized.
func DecodeFuseState(cid string) (string, bool) {
	s := strings.TrimPrefix(cid, "0x")
	if len(s) < 8 {
		return "", false
	}
	d0, err := strconv.ParseUint(s[0:8], 16, 32)
	if err != nil {
		return "", false
	}
	flval := fmt.Sprintf("%x%02x", (d0>>28)&0x8, (d0>>20)&0xf0)
	switch flval {
	case "800":
		return "NS (unfused, no secure-boot fuses)", true
	case "810", "820", "830", "840", "850":
		return "PKC (public-key secure boot)", true
	case "890", "8a0", "8b0", "8c0", "8d0":
		return "SBKPKC (SBK + secure boot)", true
	case "000":
		return "non-production chip", true
	default:
		return "unrecognized (0x" + flval + ")", true
	}
}

// ReadBRCID reads the chip's BR_CID, which the Tegra bootrom exposes as USB
// string descriptor #3 (tegrarcm_v2 NvTegraReadUidT23x: GET_DESCRIPTOR string 3,
// wIndex 0). Returns the formatted CID (e.g. "0x80012344...") and the raw
// descriptor bytes. The low nibble of CID dword0 bits [27:24] gives the fuse
// state: 0 = NS (unfused), 1-5 = PKC, 9-d = SBKPKC.
func (d *Device) ReadBRCID() (string, []byte, error) {
	raw, err := d.controlIn(0x06, 0x0303, 0, 0x60, 5000)
	if err != nil {
		return "", nil, err
	}
	if len(raw) == 0 || raw[0] == 0 || raw[0]&1 != 0 {
		return "", raw, fmt.Errorf("unexpected BR_CID descriptor (%d bytes)", len(raw))
	}
	bLen := int(raw[0])
	if bLen > len(raw) {
		bLen = len(raw)
	}
	// tegrarcm reverses the descriptor body [2..bLen-1], then reads every second
	// byte from index 3 to form the hex string.
	buf := make([]byte, len(raw))
	copy(buf, raw)
	for i, j := 2, bLen-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	var cid []byte
	for i := 1; i < bLen-2; i += 2 {
		cid = append(cid, buf[i+2])
	}
	return "0x" + string(cid), raw, nil
}

// ResolveRcmBlobs finds the standard T234 RCM-boot blobs in dir, in boot order,
// plus the applet. Filenames follow NVIDIA's rcmdump/flash staging.
func ResolveRcmBlobs(dir string) (bootBlobs []string, applet string, err error) {
	find := func(patterns ...string) (string, error) {
		for _, p := range patterns {
			m, _ := filepath.Glob(filepath.Join(dir, p))
			if len(m) > 0 {
				return m[0], nil
			}
		}
		return "", fmt.Errorf("no blob matching %v in %s", patterns, dir)
	}
	order := []struct {
		name string
		pats []string
	}{
		{"bct_br", []string{"br_bct_BR.bct", "br_bct*.bct"}},
		{"mb1", []string{"mb1_t234*sigheader.bin.encrypt", "mb1_t234*.bin.encrypt"}},
		{"psc_bl1", []string{"psc_bl1_*sigheader.bin.encrypt", "psc_bl1_*.bin.encrypt"}},
		{"bct_mb1", []string{"mb1_bct_MB1*sigheader.bct.encrypt", "mb1_bct_MB1*.encrypt"}},
	}
	for _, o := range order {
		f, e := find(o.pats...)
		if e != nil {
			return nil, "", fmt.Errorf("%s: %w", o.name, e)
		}
		bootBlobs = append(bootBlobs, f)
	}
	applet, err = find("applet_t234*sigheader.bin.encrypt", "applet_*.bin.encrypt")
	if err != nil {
		return nil, "", err
	}
	return bootBlobs, applet, nil
}

// PollBootloader reads the bootloader status the device reports once the early
// boot chain (bct_br, mb1, psc_bl1, bct_mb1) is up: a 0x44-byte bulk-IN on EP
// 0x81 holding a 64-byte version string and a u32 last_boot_error (tegrarcm_v2
// --pollbl / mainT23x). It blocks until the device is ready, so call it before
// downloading the applet.
func (d *Device) PollBootloader() (version string, lastBootError uint32, err error) {
	buf, err := d.BulkIn(0x44, 5000)
	if err != nil {
		return "", 0, err
	}
	if len(buf) >= 0x40 {
		version = string(bytes.TrimRight(buf[:0x40], "\x00"))
	}
	if len(buf) >= 0x44 {
		lastBootError = binary.LittleEndian.Uint32(buf[0x40:0x44])
	}
	return version, lastBootError, nil
}

// FullRcmBoot runs the whole T234 RCM boot in a single USB session, with no
// gaps: read UID, bulk-OUT the four bootrom blobs, poll the bootloader, then
// bulk-OUT the applet. It must be fast and uninterrupted — if the applet does
// not arrive promptly after the bootrom blobs, MB1 falls back to booting the
// on-flash OS instead of the applet (the device re-enumerates as 0955:7020).
func (d *Device) FullRcmBoot(bootBlobs []string, appletBlob string) error {
	if cid, _, err := d.ReadBRCID(); err == nil {
		fmt.Printf("BR_CID: %s\n", cid)
	}
	if err := d.RcmBoot(bootBlobs); err != nil {
		return err
	}
	ver, lastErr, err := d.PollBootloader()
	if err != nil {
		return fmt.Errorf("pollbl: %w", err)
	}
	fmt.Printf("BL: version %q last_boot_error=%d\n", ver, lastErr)
	if err := d.RcmBoot([]string{appletBlob}); err != nil {
		return err
	}
	// Give mb2_applet a moment to come up, then confirm it over the 3p protocol.
	time.Sleep(500 * time.Millisecond)
	fmt.Println("Probing mb2 applet (3p)...")
	if err := newThreeP(d).ProbeVersion(); err != nil {
		return fmt.Errorf("mb2 probe: %w", err)
	}
	return nil
}

// RcmBoot sends the given signed blob files to the bootrom over bulk-OUT, in
// order. For T234 this is exactly what tegrarcm_v2's --download does
// (RcmDownLoadImages): each file is written raw, with no RCM framing and no
// per-blob status read. The boot order is bct_br, mb1, psc_bl1, bct_mb1, then
// (after the bootloader is polled) applet.
func (d *Device) RcmBoot(files []string) error {
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		fmt.Printf("Sending %s (%d bytes)... ", filepath.Base(f), len(data))
		start := time.Now()
		if err := d.BulkOut(data, 10000); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("download %s: %w", filepath.Base(f), err)
		}
		fmt.Printf("ok (%s)\n", time.Since(start).Round(time.Millisecond))
	}
	return nil
}

// ResolveFlashBootBlobs finds the full-flash RCM-boot blobs in dir: the four
// bootrom blobs, plus the post-pollbl memory BCT and the ~100 MB flashing blob
// (blob.bin) that carries the flashing kernel/initrd. From tegrarcm's
// rcmbootcmd.txt (tegra-flash-helper --no-flash --rcm-boot).
func ResolveFlashBootBlobs(dir string) (bootBlobs, postBlobs []string, err error) {
	find := func(patterns ...string) (string, error) {
		for _, p := range patterns {
			if m, _ := filepath.Glob(filepath.Join(dir, p)); len(m) > 0 {
				return m[0], nil
			}
		}
		return "", fmt.Errorf("no blob matching %v in %s", patterns, dir)
	}
	for _, b := range []struct {
		name string
		pats []string
	}{
		{"bct_br", []string{"br_bct_BR.bct", "br_bct*.bct"}},
		{"mb1", []string{"mb1_t234*sigheader.bin.encrypt", "mb1_t234*.bin.encrypt"}},
		{"psc_bl1", []string{"psc_bl1_*sigheader.bin.encrypt", "psc_bl1_*.bin.encrypt"}},
		{"bct_mb1", []string{"mb1_bct_MB1*sigheader.bct.encrypt", "mb1_bct_MB1*.encrypt"}},
	} {
		f, e := find(b.pats...)
		if e != nil {
			return nil, nil, fmt.Errorf("%s: %w", b.name, e)
		}
		bootBlobs = append(bootBlobs, f)
	}
	mem, e := find("mem_rcm*sigheader.bct.encrypt", "mem_rcm*.bct.encrypt")
	if e != nil {
		return nil, nil, fmt.Errorf("bct_mem: %w", e)
	}
	blob, e := find("blob.bin")
	if e != nil {
		return nil, nil, fmt.Errorf("blob: %w", e)
	}
	return bootBlobs, []string{mem, blob}, nil
}

// FlashBoot runs the full-flash RCM boot in one session: UID, the four bootrom
// blobs, pollbl, then the memory BCT and the flashing blob. The flashing blob
// boots a recovery kernel/initrd, after which the device re-enumerates as a USB
// mass-storage gadget that the rootfs is written to.
func (d *Device) FlashBoot(bootBlobs, postBlobs []string) error {
	if cid, _, err := d.ReadBRCID(); err == nil {
		fmt.Printf("BR_CID: %s\n", cid)
	}
	if err := d.RcmBoot(bootBlobs); err != nil {
		return err
	}
	ver, lastErr, err := d.PollBootloader()
	if err != nil {
		return fmt.Errorf("pollbl: %w", err)
	}
	fmt.Printf("BL: version %q last_boot_error=%d\n", ver, lastErr)
	return d.RcmBoot(postBlobs)
}
