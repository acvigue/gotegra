//go:build darwin

package gotegra

import "github.com/ebitengine/purego"

var defaultLibusbPaths = []string{
	"/opt/homebrew/lib/libusb-1.0.dylib",
	"/usr/local/lib/libusb-1.0.dylib",
	"libusb-1.0.dylib",
}

func openLib(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}
