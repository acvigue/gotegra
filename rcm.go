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

// Fuse modes FuseMode reports.
const (
	FuseNS     = "NS"     // unfused: the boot ROM takes zero-key signed files
	FusePKC    = "PKC"    // PublicKeyHash burned: PKC-signed files only
	FuseSBKPKC = "SBKPKC" // SBK and PKC: encrypted and PKC-signed files only
)

// fuseBits returns the fuse-state digits of a BR_CID string ("0x" + 32 hex
// chars) the way NVIDIA's tegra-flash-helper.sh (chip 0x23) forms them. The
// state lives in dword0: bit 31 = production, bits [27:24] select the mode.
func fuseBits(cid string) (string, bool) {
	s := strings.TrimPrefix(cid, "0x")
	if len(s) < 8 {
		return "", false
	}
	d0, err := strconv.ParseUint(s[0:8], 16, 32)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%x%02x", (d0>>28)&0x8, (d0>>20)&0xf0), true
}

// FuseMode returns FuseNS, FusePKC or FuseSBKPKC for a BR_CID string, or ""
// for a non-production chip or a state it does not know.
func FuseMode(cid string) string {
	flval, ok := fuseBits(cid)
	if !ok {
		return ""
	}
	switch flval {
	case "800":
		return FuseNS
	case "810", "820", "830", "840", "850":
		return FusePKC
	case "890", "8a0", "8b0", "8c0", "8d0":
		return FuseSBKPKC
	}
	return ""
}

// DecodeFuseState decodes the fuse / secure-boot state from a BR_CID string
// ("0x" + 32 hex chars), matching NVIDIA's tegra-flash-helper.sh chip-0x23
// branch. Returns a human string and whether the CID could be read at all.
func DecodeFuseState(cid string) (string, bool) {
	flval, ok := fuseBits(cid)
	if !ok {
		return "", false
	}
	switch FuseMode(cid) {
	case FuseNS:
		return "NS (unfused, no secure-boot fuses)", true
	case FusePKC:
		return "PKC (public-key secure boot)", true
	case FuseSBKPKC:
		return "SBKPKC (SBK + secure boot)", true
	}
	if flval == "000" {
		return "non-production chip", true
	}
	return "unrecognized (0x" + flval + ")", true
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

// How a set of boot blobs is signed, which is also the suffix tegraflash gives
// the files: <file>.encrypt with the zero key, <file>.signed with a PKC key.
const (
	SignedZeroKey = "encrypt" // for an unfused (NS) unit
	SignedPKC     = "signed"  // for a unit whose PublicKeyHash fuse is burned
)

// blobSpec names one signed boot blob; each pattern takes the signing suffix.
type blobSpec struct {
	name string
	pats []string
}

var (
	specMB1    = blobSpec{"mb1", []string{"mb1_t234*sigheader.bin.%s", "mb1_t234*.bin.%s"}}
	specPscBl1 = blobSpec{"psc_bl1", []string{"psc_bl1_*sigheader.bin.%s", "psc_bl1_*.bin.%s"}}
	specBctMB1 = blobSpec{"bct_mb1", []string{"mb1_bct_MB1*sigheader.bct.%s", "mb1_bct_MB1*.%s"}}
	specBctMem = blobSpec{"bct_mem", []string{"mem_rcm*sigheader.bct.%s", "mem_rcm*.bct.%s"}}
	specApplet = blobSpec{"applet", []string{"applet_t234*sigheader.bin.%s", "applet_*.bin.%s"}}
)

// findBlob returns the first file in dir matching one of the patterns.
func findBlob(dir string, patterns ...string) (string, error) {
	for _, p := range patterns {
		if m, _ := filepath.Glob(filepath.Join(dir, p)); len(m) > 0 {
			return m[0], nil
		}
	}
	return "", fmt.Errorf("no blob matching %v in %s", patterns, dir)
}

// resolveSigned finds one file per spec in dir, all signed the same way, and
// says which way. It refuses a directory that holds zero-key and PKC-signed
// files side by side: picked by name they would be sent as one set, and no
// unit boots a mix (a plain and a PKC build of one commit, copied into the same
// directory, look like that).
func resolveSigned(dir string, specs []blobSpec) (files []string, signing string, err error) {
	found := map[string][]string{}
	count := map[string]int{}
	for _, kind := range []string{SignedZeroKey, SignedPKC} {
		row := make([]string, len(specs))
		for i, sp := range specs {
			pats := make([]string, len(sp.pats))
			for j, p := range sp.pats {
				pats[j] = fmt.Sprintf(p, kind)
			}
			if f, e := findBlob(dir, pats...); e == nil {
				row[i] = f
				count[kind]++
			}
		}
		found[kind] = row
	}
	switch {
	case count[SignedZeroKey] > 0 && count[SignedPKC] > 0:
		return nil, "", fmt.Errorf("%s holds both zero-key (*.%s) and PKC-signed (*.%s) boot files; "+
			"that is two builds in one directory, use a directory with one of them",
			dir, SignedZeroKey, SignedPKC)
	case count[SignedPKC] > 0:
		signing = SignedPKC
	default:
		signing = SignedZeroKey
	}
	for i, sp := range specs {
		if found[signing][i] != "" {
			continue
		}
		// nothing signed at all in dir: name both spellings; otherwise the set is
		// of one kind and this file of that kind is missing
		kinds := []string{signing}
		if count[signing] == 0 {
			kinds = []string{SignedZeroKey, SignedPKC}
		}
		var pats []string
		for _, kind := range kinds {
			for _, p := range sp.pats {
				pats = append(pats, fmt.Sprintf(p, kind))
			}
		}
		return nil, "", fmt.Errorf("%s: no blob matching %v in %s", sp.name, pats, dir)
	}
	return found[signing], signing, nil
}

// BlobSigning says how a resolved set of boot blobs is signed (SignedZeroKey or
// SignedPKC), from the name of the first signed file in it; "" if none is.
func BlobSigning(blobs []string) string {
	for _, b := range blobs {
		switch strings.TrimPrefix(filepath.Ext(b), ".") {
		case SignedZeroKey:
			return SignedZeroKey
		case SignedPKC:
			return SignedPKC
		}
	}
	return ""
}

// CheckSigning refuses boot blobs the unit's boot ROM does not take: PKC-signed
// files on an unfused unit, zero-key files on a fused one. NVIDIA's flasher
// draws the same line (tegra-flash-helper.sh: a secured target needs the key,
// an unsecured one gets none). Sending the wrong kind burns nothing, but the
// boot ROM stops answering and the unit has to be put into recovery mode again.
// A fuse state it does not know is let through.
func CheckSigning(cid string, blobs []string) error {
	mode, signing := FuseMode(cid), BlobSigning(blobs)
	switch {
	case mode == FuseNS && signing == SignedPKC:
		return fmt.Errorf("the unit is unfused (NS) and these boot files are PKC-signed (*.%s): "+
			"it needs the zero-key files (*.%s) of a build without a PKC key", SignedPKC, SignedZeroKey)
	case (mode == FusePKC || mode == FuseSBKPKC) && signing == SignedZeroKey:
		return fmt.Errorf("the unit is fused (%s) and these boot files are zero-key signed (*.%s): "+
			"it needs the files of a build signed with its PKC key (*.%s)", mode, SignedZeroKey, SignedPKC)
	}
	return nil
}

// ResolveRcmBlobs finds the standard T234 RCM-boot blobs in dir, in boot order,
// plus the applet. Filenames follow NVIDIA's rcmdump/flash staging; the signed
// ones end in .encrypt (zero key) or .signed (PKC key), all the same in one dir.
func ResolveRcmBlobs(dir string) (bootBlobs []string, applet string, err error) {
	bct, err := findBlob(dir, "br_bct_BR.bct", "br_bct*.bct")
	if err != nil {
		return nil, "", fmt.Errorf("bct_br: %w", err)
	}
	files, _, err := resolveSigned(dir, []blobSpec{specMB1, specPscBl1, specBctMB1, specApplet})
	if err != nil {
		return nil, "", err
	}
	return append([]string{bct}, files[:3]...), files[3], nil
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
		if err := CheckSigning(cid, bootBlobs); err != nil {
			return err
		}
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
	bct, err := findBlob(dir, "br_bct_BR.bct", "br_bct*.bct")
	if err != nil {
		return nil, nil, fmt.Errorf("bct_br: %w", err)
	}
	files, _, err := resolveSigned(dir, []blobSpec{specMB1, specPscBl1, specBctMB1, specBctMem})
	if err != nil {
		return nil, nil, err
	}
	blob, err := findBlob(dir, "blob.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("blob: %w", err)
	}
	return append([]string{bct}, files[:3]...), []string{files[3], blob}, nil
}

// FlashBoot runs the full-flash RCM boot in one session: UID, the four bootrom
// blobs, pollbl, then the memory BCT and the flashing blob. The flashing blob
// boots a recovery kernel/initrd, after which the device re-enumerates as a USB
// mass-storage gadget that the rootfs is written to.
func (d *Device) FlashBoot(bootBlobs, postBlobs []string) error {
	if cid, _, err := d.ReadBRCID(); err == nil {
		fmt.Printf("BR_CID: %s\n", cid)
		if err := CheckSigning(cid, bootBlobs); err != nil {
			return err
		}
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
