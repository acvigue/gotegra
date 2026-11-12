//go:build !darwin

package gotegra

import (
	"fmt"
	"time"
)

// The mass-storage flash stage is implemented only on macOS for now (it drives
// diskutil/ioreg and raw /dev/rdiskN writes). A Linux port would use the l4t
// initrd-flash host tooling (udev names, mount + make-sdcard) directly.

var errDarwinOnly = fmt.Errorf("the gotegra flashing stage is only implemented on macOS")

// FlashOptions tunes the mass-storage stages (see the darwin implementation).
type FlashOptions struct{ NoErase bool }

func FlashWrite(flashpkgImg, nvmeImg string) error { return errDarwinOnly }
func FlashWritePartsWith(flashpkgImg, partsDir, rootfsName string, o FlashOptions) error {
	return errDarwinOnly
}
func FlashAllWith(rcmbootDir, flashpkgImg, partsDir, rootfsName string, o FlashOptions) error {
	return errDarwinOnly
}
func FlashQspi(rcmbootDir, flashpkgImg string) error     { return errDarwinOnly }
func FlashResumeParts(partsDir, rootfsName string) error { return errDarwinOnly }
func CaptureStatus() error                               { return errDarwinOnly }

type RunPkgOptions struct {
	PartsDir, RootfsName string
	NvmeWait, RCMWait    time.Duration
}

func RunPkg(rcmbootDir, flashpkgImg string, o RunPkgOptions) error { return errDarwinOnly }
func ProbeNvme(rcmbootDir, flashpkgImg string) error               { return errDarwinOnly }
