//go:build windows

package gotegra

import "syscall"

var defaultLibusbPaths = []string{
	"libusb-1.0.dll",
	`C:\Program Files\libusb\libusb-1.0.dll`,
}

func openLib(path string) (uintptr, error) {
	h, err := syscall.LoadLibrary(path)
	return uintptr(h), err
}
