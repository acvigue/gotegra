//go:build !darwin

package gotegra

import "fmt"

// FlashWrite is implemented only on macOS for now (it drives diskutil and raw
// /dev/rdiskN writes). A Linux port would use the l4t initrd-flash host tooling
// (mount + make-sdcard) directly.
func FlashWrite(flashpkgImg, nvmeImg string) error {
	return fmt.Errorf("gotegra flashwrite is only implemented on macOS")
}
