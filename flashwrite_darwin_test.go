//go:build darwin

package gotegra

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIoregInt(t *testing.T) {
	block := `Foo@1  <class IOUSBHostDevice>
    "idProduct" = 260
    "idVendor" = 7531
`
	if v := ioregInt(block, `"idVendor" = `); v != VendorLinuxFdn {
		t.Fatalf("idVendor = %d, want %d", v, VendorLinuxFdn)
	}
	if p := ioregInt(block, `"idProduct" = `); p != ProductL4TFlash {
		t.Fatalf("idProduct = %d, want %d", p, ProductL4TFlash)
	}
	if ioregInt(block, `"bcdDevice" = `) != -1 {
		t.Fatal("missing key should give -1")
	}
}

func TestUsbPresenceRuns(t *testing.T) {
	s := usbPresence()
	if s == "" {
		t.Fatal("empty presence string")
	}
	t.Log(s)
}

func TestLunName(t *testing.T) {
	li := lunInfo{vendor: "flashpkg", product: "175b9621", media: "175b9621", size: 134217728}
	if li.name() != lunFlashpkg {
		t.Fatalf("flashpkg LUN not recognized: %q", li.name())
	}
	li = lunInfo{vendor: "nvme0n1", product: "175b9621", size: 256 << 30}
	if li.name() != lunNvme {
		t.Fatalf("nvme LUN not recognized: %q", li.name())
	}
	li = lunInfo{vendor: "Samsung", product: "PSSD T7", media: "Samsung PSSD T7 Media", size: 1 << 40}
	if li.name() != "" {
		t.Fatalf("foreign disk accepted as %q", li.name())
	}
	// the media name alone (what diskutil shows) must NOT be enough
	li = lunInfo{media: "175b9621", size: 134217728}
	if li.name() != "" {
		t.Fatalf("untagged disk accepted as %q", li.name())
	}
}

func TestIoregStr(t *testing.T) {
	line := `|   "Device Characteristics" = {"Vendor Name"="flashpkg","Product Name"="175b9621","Product Revision Level"="0404"}`
	if v := ioregStr(line, `"Vendor Name"=`); v != "flashpkg" {
		t.Fatalf("vendor = %q", v)
	}
	if p := ioregStr(line, `"Product Name"=`); p != "175b9621" {
		t.Fatalf("product = %q", p)
	}
	if ioregStr(`    "BSD Name" = "disk4"`, `"BSD Name" = `) != "disk4" {
		t.Fatal("BSD Name not parsed")
	}
	if !wholeDiskRe.MatchString("disk4") || wholeDiskRe.MatchString("disk4s1") {
		t.Fatal("whole-disk regexp wrong")
	}
}

func TestBlockDeviceIdentityRuns(t *testing.T) {
	ids := blockDeviceIdentity()
	if _, ok := ids["/dev/disk0"]; !ok {
		t.Fatalf("internal disk0 not found in %v", ids)
	}
	t.Log(ids)
}

func TestTailLines(t *testing.T) {
	out := tailLines("a\nb\nc\nd\n", 2)
	if !strings.Contains(out, "2 earlier lines") || !strings.Contains(out, "    c\n    d\n") {
		t.Fatalf("unexpected tail:\n%s", out)
	}
	if tailLines("", 3) != "" {
		t.Fatal("empty input should give empty output")
	}
}

func TestBuildFlashpkg(t *testing.T) {
	if _, err := exec.LookPath("7z"); err != nil {
		t.Skip("7z not installed")
	}
	img := filepath.Join(t.TempDir(), "probe.img")
	if err := buildFlashpkg(img, "export-devices nvme0n1\nreboot\n"); err != nil {
		t.Skipf("buildFlashpkg: %v", err)
	}
	st, err := os.Stat(img)
	if err != nil || st.Size() != 128<<20 {
		t.Fatalf("image size: %v %d", err, st.Size())
	}
	dir := t.TempDir()
	if out, err := exec.Command("7z", "x", "-y", "-o"+dir, img, "flashpkg/conf/command_sequence").CombinedOutput(); err != nil {
		t.Fatalf("7z: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(dir, "flashpkg", "conf", "command_sequence"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "export-devices nvme0n1\nreboot\n" {
		t.Fatalf("command_sequence = %q", got)
	}
}

func TestLoadPartsPreflight(t *testing.T) {
	dir := t.TempDir()
	idx := "0, 9:0:primary_gpt, 512, 19968, gpt.bin, 16896, fixed-<reserved>-0, aa\n" +
		"4, 9:0:A_reserved_on_user, 135024640, 33161216, , , fixed-<reserved>-5, \n" +
		"16, 9:0:APP, 1561624576, 4096, , , fixed-<reserved>-1, \n"
	write := func(name string, n int) {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "flash.idx"), []byte(idx), 0o644); err != nil {
		t.Fatal(err)
	}
	rootfs := ""
	_, err := loadParts(dir, &rootfs)
	if err == nil || !strings.Contains(err.Error(), "gpt.bin is missing") || !strings.Contains(err.Error(), "rootfs image luka-image.ext4 is missing") {
		t.Fatalf("missing images not reported: %v", err)
	}
	write("gpt.bin", 16896)
	write("luka-image.ext4", 8192) // larger than the 4096-byte APP partition
	if _, err := loadParts(dir, &rootfs); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized rootfs not reported: %v", err)
	}
	write("luka-image.ext4", 4096)
	parts, err := loadParts(dir, &rootfs)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 3 || parts[0].name != "primary_gpt" || parts[0].start != 512 || parts[2].image(dir, rootfs) != filepath.Join(dir, "luka-image.ext4") || parts[1].image(dir, rootfs) != "" {
		t.Fatalf("parsed parts wrong: %+v", parts)
	}
}

func TestProgressPortFromIoreg(t *testing.T) {
	out := `+-o Linux for Tegra@01100000  <class IOUSBHostDevice, id 0x1, registered, matched, active, busy 0, retain 20>
  | {
  |   "USB Product Name" = "Linux for Tegra"
  | }
  +-o IOUSBHostInterface@0  <class IOUSBHostInterface>
+-o L4T flash progress@01100000  <class IOUSBHostDevice, id 0x2, registered, matched, active, busy 0, retain 20>
  | {
  |   "idProduct" = 261
  |   "USB Product Name" = "L4T flash progress"
  | }
  +-o IOUSBHostInterface@0  <class IOUSBHostInterface>
    +-o AppleUSBACMData  <class AppleUSBACMData>
      +-o IOSerialBSDClient  <class IOSerialBSDClient>
            {
              "IOCalloutDevice" = "/dev/cu.usbmodem175b96211"
              "IODialinDevice" = "/dev/tty.usbmodem175b96211"
            }
`
	if got := progressPortFromIoreg(out); got != "/dev/cu.usbmodem175b96211" {
		t.Errorf("got %q", got)
	}
	if got := progressPortFromIoreg(`+-o Some Modem@1  <class IOUSBHostDevice>
  | "USB Product Name" = "Some Modem"
      "IOCalloutDevice" = "/dev/cu.usbmodem1"
`); got != "" {
		t.Errorf("foreign modem matched: %q", got)
	}
}
