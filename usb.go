// Package tegra talks to an NVIDIA Tegra SoC in RCM (recovery) mode over USB,
// with no cgo: libusb-1.0 is bound at runtime with purego, the same approach
// internal/jlink uses for the J-Link DLL.
//
// It exists because NVIDIA's own flashing stack (tegrarcm_v2 etc.) is a Linux
// x86 binary that drives the device through Linux usbdevfs ioctls, and the only
// way to run it on this Mac is a QEMU x86 guest whose emulated USB passthrough
// cannot complete the RCM bulk-OUT transfers. Doing the USB natively here, via
// libusb, sidesteps that entirely.
//
// The protocol constants below are reconstructed from tegrarcm_v2 (T234 path,
// mainT23x / RcmDownLoadImages / NvTegraUsbCtrlReadTimeout): the BR_CID is USB
// string descriptor #3, blob downloads are raw bulk-OUT on EP 0x01, and bulk IN
// is EP 0x81.
package gotegra

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

// USB identity and endpoints of a Tegra device in RCM (recovery) mode.
const (
	VendorNVIDIA = 0x0955
	ProductT234  = 0x7323 // Orin (T234) APX

	// The flashing initrd (once RCM-booted) comes up as this USB gadget — the
	// "Linux for Tegra" mass-storage device (gadget-vid-pid-remove 1d6b:104).
	VendorLinuxFdn  = 0x1d6b
	ProductL4TFlash = 0x0104
	// The agent's progress gadget (CDC-ACM), bound only between LUNs.
	ProductL4TProgress = 0x0105

	epBulkOut = 0x01
	epBulkIn  = 0x81

	// tegrarcm_v2 writes/reads usbdevfs bulk URBs in 16 KiB chunks; mirror that.
	bulkChunk = 0x4000
)

// DisconnectGadget signals the Tegra flashing gadget (1d6b:0104) that the host
// is done with the current mass-storage LUN, so the device-side initrd agent's
// wait_for_disconnect returns and it moves on (mount the flashpkg, or export the
// next block device). That agent polls /sys/class/udc/<udc>/state once per
// second and proceeds only when it reads a state other than "configured".
//
// The reliable way to trip that is SET_CONFIGURATION 0: it leaves the gadget in
// the "addressed" (un-configured) state and HOLDS it there — while we keep the
// device open (seized) macOS cannot re-configure it — so the 1 s poll is certain
// to sample it. We hold briefly, by which point the device has seen the
// disconnect and unbound its own UDC. A bare USB reset (ReEnumerate) only
// un-configures for the few-hundred-ms re-enumeration window, which the 1 s poll
// usually misses — that is why `diskutil eject` and a plain reset both hung. We
// fall back to a reset only if SET_CONFIGURATION is refused. Returns the method
// used, for logging. Not-open is reported so the caller can retry or prompt.
func DisconnectGadget() (string, error) {
	lib, err := loadLibusb()
	if err != nil {
		return "", err
	}
	var ctx uintptr
	if rc := lib.Init(&ctx); rc != 0 {
		return "", fmt.Errorf("libusb_init: %s", lib.strerr(rc))
	}
	defer lib.Exit(ctx)
	h := lib.OpenVIDPID(ctx, VendorLinuxFdn, ProductL4TFlash)
	if h == 0 {
		return "", fmt.Errorf("flashing gadget %04x:%04x not open", VendorLinuxFdn, ProductL4TFlash)
	}
	defer lib.Close(h)
	if rc := lib.SetConfiguration(h, 0); rc == 0 {
		// Hold the un-configured state (seized, so macOS cannot re-configure)
		// long enough for the agent's 1 s poll to sample it and unbind the UDC.
		time.Sleep(2500 * time.Millisecond)
		return "unconfigure", nil
	} else if rcR := lib.ResetDevice(h); rcR == 0 {
		return fmt.Sprintf("reset-fallback (set_config0=%s)", lib.strerr(rc)), nil
	} else {
		return "", fmt.Errorf("set_config(0)=%s, reset=%s", lib.strerr(rc), lib.strerr(rcR))
	}
}

// libusb binds the handful of libusb-1.0 entry points we need. Signatures match
// libusb.h; purego marshals the integer/pointer args without cgo.
type libusb struct {
	Init             func(ctx *uintptr) int32
	Exit             func(ctx uintptr)
	OpenVIDPID       func(ctx uintptr, vid, pid uint16) uintptr
	Close            func(dev uintptr)
	SetConfiguration func(dev uintptr, config int32) int32
	ClaimInterface   func(dev uintptr, iface int32) int32
	ReleaseInterface func(dev uintptr, iface int32) int32
	SetAutoDetach    func(dev uintptr, enable int32) int32
	ResetDevice      func(dev uintptr) int32
	BulkTransfer     func(dev uintptr, endpoint uint8, data *byte, length int32, transferred *int32, timeout uint32) int32
	ControlTransfer  func(dev uintptr, bmReqType, bRequest uint8, wValue, wIndex uint16, data *byte, wLength uint16, timeout uint32) int32
	StrError         func(code int32) *byte // const char *
}

func loadLibusb() (*libusb, error) {
	var lastErr error
	for _, p := range defaultLibusbPaths {
		h, err := openLib(p)
		if err != nil || h == 0 {
			if err != nil {
				lastErr = err
			}
			continue
		}
		l := &libusb{}
		for _, r := range []struct {
			fn   any
			name string
		}{
			{&l.Init, "libusb_init"},
			{&l.Exit, "libusb_exit"},
			{&l.OpenVIDPID, "libusb_open_device_with_vid_pid"},
			{&l.Close, "libusb_close"},
			{&l.SetConfiguration, "libusb_set_configuration"},
			{&l.ClaimInterface, "libusb_claim_interface"},
			{&l.ReleaseInterface, "libusb_release_interface"},
			{&l.SetAutoDetach, "libusb_set_auto_detach_kernel_driver"},
			{&l.ResetDevice, "libusb_reset_device"},
			{&l.BulkTransfer, "libusb_bulk_transfer"},
			{&l.ControlTransfer, "libusb_control_transfer"},
			{&l.StrError, "libusb_strerror"},
		} {
			if err := register(r.fn, h, r.name); err != nil {
				return nil, fmt.Errorf("libusb: %s: %w", r.name, err)
			}
		}
		return l, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("libusb-1.0 not found (looked in %v)", defaultLibusbPaths)
	}
	return nil, lastErr
}

func register(fn any, h uintptr, name string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	purego.RegisterLibFunc(fn, h, name)
	return nil
}

func (l *libusb) strerr(code int32) string {
	p := l.StrError(code)
	if p == nil {
		return fmt.Sprintf("libusb error %d", code)
	}
	return fmt.Sprintf("%s (%d)", cString(p), code)
}

// Device is an open handle to a Tegra device in RCM mode.
type Device struct {
	lib    *libusb
	ctx    uintptr
	handle uintptr
}

// Open finds the T234 APX device, claims interface 0, and returns a handle.
func Open() (*Device, error) {
	lib, err := loadLibusb()
	if err != nil {
		return nil, err
	}
	var ctx uintptr
	if rc := lib.Init(&ctx); rc != 0 {
		return nil, fmt.Errorf("libusb_init: %s", lib.strerr(rc))
	}
	h := lib.OpenVIDPID(ctx, VendorNVIDIA, ProductT234)
	if h == 0 {
		lib.Exit(ctx)
		return nil, fmt.Errorf("no NVIDIA Tegra device in recovery mode (%04x:%04x) found", VendorNVIDIA, ProductT234)
	}
	d := &Device{lib: lib, ctx: ctx, handle: h}
	lib.SetAutoDetach(h, 1)    // harmless NOT_SUPPORTED on macOS
	lib.SetConfiguration(h, 1) // usually already 1; ignore result
	if rc := lib.ClaimInterface(h, 0); rc != 0 {
		d.Close()
		return nil, fmt.Errorf("claim interface 0: %s", lib.strerr(rc))
	}
	return d, nil
}

// OpenWait is Open, retried until the RCM device shows up or timeout passes —
// for chaining runs: after the agent's `reboot forced-recovery` the box takes a
// few seconds to re-enumerate as 0955:7323.
func OpenWait(timeout time.Duration) (*Device, error) {
	deadline := time.Now().Add(timeout)
	announced := false
	for {
		d, err := Open()
		if err == nil || time.Now().After(deadline) {
			return d, err
		}
		if !announced {
			fmt.Printf("waiting up to %s for the RCM device (%04x:%04x)...\n", timeout, VendorNVIDIA, ProductT234)
			announced = true
		}
		time.Sleep(time.Second)
	}
}

// Close releases the interface and frees the libusb context.
func (d *Device) Close() {
	if d == nil {
		return
	}
	if d.handle != 0 {
		d.lib.ReleaseInterface(d.handle, 0)
		d.lib.Close(d.handle)
		d.handle = 0
	}
	if d.ctx != 0 {
		d.lib.Exit(d.ctx)
		d.ctx = 0
	}
}

// BulkOut writes data to EP 0x01 in 16 KiB chunks, matching tegrarcm_v2's
// NvTegraUsbWriteTimeout. This is the transfer QEMU's emulated passthrough
// cannot complete; native libusb does it directly.
func (d *Device) BulkOut(data []byte, timeoutMS uint32) error {
	for off := 0; off < len(data); {
		n := len(data) - off
		if n > bulkChunk {
			n = bulkChunk
		}
		var transferred int32
		rc := d.lib.BulkTransfer(d.handle, epBulkOut, &data[off], int32(n), &transferred, timeoutMS)
		if rc != 0 {
			return fmt.Errorf("bulk OUT (%d/%d bytes sent): %s", off, len(data), d.lib.strerr(rc))
		}
		if transferred == 0 {
			return fmt.Errorf("bulk OUT stalled: 0 bytes transferred at offset %d/%d", off, len(data))
		}
		off += int(transferred)
	}
	return nil
}

// BulkIn reads up to n bytes from EP 0x81 and returns what arrived.
func (d *Device) BulkIn(n int, timeoutMS uint32) ([]byte, error) {
	buf := make([]byte, n)
	var transferred int32
	rc := d.lib.BulkTransfer(d.handle, epBulkIn, &buf[0], int32(n), &transferred, timeoutMS)
	if rc != 0 {
		return nil, fmt.Errorf("bulk IN: %s", d.lib.strerr(rc))
	}
	return buf[:transferred], nil
}

// controlIn issues a device-to-host control transfer and returns the data read.
func (d *Device) controlIn(bRequest uint8, wValue, wIndex, wLength uint16, timeoutMS uint32) ([]byte, error) {
	buf := make([]byte, wLength)
	rc := d.lib.ControlTransfer(d.handle, 0x80, bRequest, wValue, wIndex, &buf[0], wLength, timeoutMS)
	if rc < 0 {
		return nil, fmt.Errorf("control IN (req 0x%02x val 0x%04x): %s", bRequest, wValue, d.lib.strerr(rc))
	}
	return buf[:rc], nil
}

// cString reads a NUL-terminated C string at p.
func cString(p *byte) string {
	if p == nil {
		return ""
	}
	var b []byte
	for i := 0; ; i++ {
		c := *(*byte)(unsafe.Add(unsafe.Pointer(p), i))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}
