package gotegra

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Fuse burning for T234 / Orin via the FSKP (Factory Secure Key Provisioning)
// flow. gotegra is ONLY the RCM USB transport: the fuse values are defined
// offline in a fuse XML (fuse_t234.xml, MagicId "FUSE" = 0x45535546), compiled
// to a fuse blob by tegraparser (--fuse_info), concatenated into fskp_t234.bin
// (tegraparser --fskp_info), then encrypted + signed with the FSKP keys by
// tegrasign_v3 (AES-GCM under FSKP_EK, then HMAC-SHA256 under FSKP_AK — see
// tegraflash_oem_sign_fskp). gotegra never builds, encrypts or signs the blob;
// it transports the already-signed artifacts, exactly as it carries the signed
// flash blobs.
//
// Two real NVIDIA transports exist; gotegra implements both:
//
//  1. FSKP-as-MB2 — the path T234 tegraflash's `burnfuses` uses (production).
//     The signed fskp_t234.bin (carrying the fuse blob) is packed into blob.bin
//     as the MB2 image, and the RCM sequence is IDENTICAL to a flash RCM-boot
//     (tegraflash_send_to_bootrom + tegraflash_send_to_bootloader with
//     mb2_is_fskp=True → `tegrarcm --pollbl --download bct_mem ... --download
//     blob blob.bin`):
//
//         bct_br, mb1, psc_bl1, mb1_bct   raw bulk-OUT to the bootrom
//         pollbl                          0x44-byte bulk-IN from MB1
//         mem_rcm BCT  (--download bct_mem)  raw bulk-OUT to MB1
//         blob.bin     (--download blob)     raw bulk-OUT to MB1
//
//     When MB1 launches the FSKP MB2, it burns the fuses and reports on UART.
//     Post-pollbl `--download` to MB1 (not an applet) is raw bulk-OUT, the same
//     RcmDownLoadImages path as the bootrom blobs — confirmed from tegrarcm_v2
//     (NvTegraAppletHandleDownload falls back to the bootloader download when no
//     applet is running). This reuses gotegra's FlashBoot transport verbatim; it
//     is BurnFusesFSKP below.
//
//  2. Applet --oem burnfuses — the generic tegrarcm path. Boot an mb2_applet,
//     then send the OEM command + the fuse blob over the 3p protocol. See
//     threep.go — OemBurnFuses / Device.BurnFusesApplet.
//
// Burning fuses is IRREVERSIBLE. The CLI defaults to a dry run and gates the
// real burn behind an explicit flag; BuildFSKPBurnPlan does no USB I/O so a plan
// can be inspected with no device attached.

// FuseBlob pairs a blob file with its on-disk size, for the dry-run plan.
type FuseBlob struct {
	Path string
	Size int64
}

func statBlob(path string) (FuseBlob, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FuseBlob{}, err
	}
	return FuseBlob{Path: path, Size: fi.Size()}, nil
}

// FSKPBurnPlan describes an FSKP fuse-burn RCM session, for dry-run display and
// for the real burn. It mirrors the tegraflash FSKP `burnfuses` RCM sequence.
type FSKPBurnPlan struct {
	BootBlobs []FuseBlob // bct_br, mb1, psc_bl1, mb1_bct — raw bulk-OUT to bootrom
	MemBCT    FuseBlob   // mem_rcm BCT — --download bct_mem (raw bulk-OUT to MB1)
	Blob      FuseBlob   // blob.bin w/ the signed FSKP MB2 — --download blob
}

// ResolveFuseBlobs finds the RCM-boot blobs for an FSKP fuse-burn session in
// dir: the four bootrom blobs plus the memory BCT and blob.bin. For a fuse burn
// blob.bin is the odmfuse/FSKP output (the signed FSKP MB2 image with the fuse
// blob baked in), not a normal flashing blob; gotegra transports it opaquely.
// The RCM layout is identical to a flash RCM-boot, so this reuses
// ResolveFlashBootBlobs.
func ResolveFuseBlobs(dir string) (bootBlobs, postBlobs []string, err error) {
	return ResolveFlashBootBlobs(dir)
}

// BuildFSKPBurnPlan stats the resolved blobs and returns the burn plan. postBlobs
// must be [memBCT, blob] as returned by ResolveFuseBlobs/ResolveFlashBootBlobs.
// It does no USB I/O, so it is safe to call (and unit-test) with no device.
func BuildFSKPBurnPlan(bootBlobs, postBlobs []string) (*FSKPBurnPlan, error) {
	if len(bootBlobs) != 4 {
		return nil, fmt.Errorf("expected 4 bootrom blobs, got %d", len(bootBlobs))
	}
	if len(postBlobs) != 2 {
		return nil, fmt.Errorf("expected 2 post-pollbl blobs (mem BCT, blob), got %d", len(postBlobs))
	}
	p := &FSKPBurnPlan{}
	for _, f := range bootBlobs {
		b, err := statBlob(f)
		if err != nil {
			return nil, err
		}
		p.BootBlobs = append(p.BootBlobs, b)
	}
	var err error
	if p.MemBCT, err = statBlob(postBlobs[0]); err != nil {
		return nil, err
	}
	if p.Blob, err = statBlob(postBlobs[1]); err != nil {
		return nil, err
	}
	return p, nil
}

// String renders the FSKP burn plan as the exact RCM sequence gotegra would run,
// for the dry-run output.
func (p *FSKPBurnPlan) String() string {
	var b strings.Builder
	b.WriteString("FSKP fuse-burn RCM session (T234/Orin) — tegraflash burnfuses path:\n")
	b.WriteString("  1. bulk-OUT the bootrom blobs to the bootrom (EP 0x01):\n")
	for i, f := range p.BootBlobs {
		fmt.Fprintf(&b, "       [%d] %s (%d bytes)\n", i, filepath.Base(f.Path), f.Size)
	}
	b.WriteString("  2. pollbl: 0x44-byte bulk-IN from MB1 (EP 0x81)\n")
	fmt.Fprintf(&b, "  3. --download bct_mem: bulk-OUT %s (%d bytes)\n", filepath.Base(p.MemBCT.Path), p.MemBCT.Size)
	fmt.Fprintf(&b, "  4. --download blob:    bulk-OUT %s (%d bytes)  <- signed FSKP MB2 + fuse blob\n", filepath.Base(p.Blob.Path), p.Blob.Size)
	b.WriteString("  5. MB1 launches the FSKP MB2, which BURNS THE FUSES (result on UART)\n")
	return b.String()
}

// bootOrder returns the boot-order blob paths for the real burn.
func (p *FSKPBurnPlan) bootOrder() []string {
	out := make([]string, 0, len(p.BootBlobs))
	for _, f := range p.BootBlobs {
		out = append(out, f.Path)
	}
	return out
}

// BurnFusesFSKP runs the FSKP fuse-burn RCM session in one USB session: read the
// current CID/fuse state, bulk-OUT the four bootrom blobs, poll the bootloader,
// then bulk-OUT the memory BCT and blob.bin (the signed FSKP MB2 that burns the
// fuses). This is the production T234 path and uses the same raw bulk-OUT
// transport as FlashBoot. IRREVERSIBLE — the caller must have confirmed intent.
func (d *Device) BurnFusesFSKP(plan *FSKPBurnPlan) error {
	if cid, _, err := d.ReadBRCID(); err == nil {
		fmt.Printf("BR_CID: %s\n", cid)
		if st, ok := DecodeFuseState(cid); ok {
			fmt.Printf("current fuse/secure-boot state: %s\n", st)
		}
	}
	fmt.Println("RCM-booting the FSKP fuse-burn chain (bootrom blobs)...")
	if err := d.RcmBoot(plan.bootOrder()); err != nil {
		return err
	}
	ver, lastErr, err := d.PollBootloader()
	if err != nil {
		return fmt.Errorf("pollbl: %w", err)
	}
	fmt.Printf("BL: version %q last_boot_error=%d\n", ver, lastErr)
	fmt.Println("Applying the signed FSKP fuse blob (mem BCT + blob.bin)...")
	if err := d.RcmBoot([]string{plan.MemBCT.Path, plan.Blob.Path}); err != nil {
		return err
	}
	fmt.Println("FSKP blob applied; the device burns the fuses and reports the result on UART.")
	return nil
}
