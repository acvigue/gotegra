//go:build linux

package gotegra

import "github.com/ebitengine/purego"

var defaultLibusbPaths = []string{
	"libusb-1.0.so.0",
	"/usr/lib/x86_64-linux-gnu/libusb-1.0.so.0",
	"/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0",
	"/usr/lib/libusb-1.0.so.0",
	"/usr/local/lib/libusb-1.0.so.0",
}

func openLib(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}
