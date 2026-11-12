package gotegra

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const realRootfs = "/Users/aiden/luka-flash/flashpack-0b6ce04-full-uefi/flashpack/flashparts/luka-image.ext4"
const realFlashpkg = "/Users/aiden/luka-flash/flashpack-0b6ce04-full-uefi/flashpack/flashpkg.img"

func TestExt4MetadataRangesNotExt4(t *testing.T) {
	p := filepath.Join(t.TempDir(), "zeros.img")
	if err := os.WriteFile(p, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := Ext4MetadataRanges(p)
	if err != nil || rs != nil {
		t.Fatalf("zeros: ranges %v err %v", rs, err)
	}
	small := filepath.Join(t.TempDir(), "small.img")
	os.WriteFile(small, []byte("x"), 0o644)
	if rs, err := Ext4MetadataRanges(small); err != nil || rs != nil {
		t.Fatalf("small: ranges %v err %v", rs, err)
	}
}

func TestExt4MetadataRangesRealImage(t *testing.T) {
	if _, err := os.Stat(realRootfs); err != nil {
		t.Skip("real rootfs image not present")
	}
	rs, err := Ext4MetadataRanges(realRootfs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("no ranges for an ext4 image")
	}
	set := &rangeSet{rs: rs}
	total := set.total()
	// 256 groups x 8 MiB inode tables = 2 GiB, plus bitmaps and GDT copies.
	if total < 2<<30 || total > 2<<30+256<<20 {
		t.Fatalf("forced total %d MiB, want ~2048 MiB", total>>20)
	}
	if rs[0].off != 0 {
		t.Fatalf("first range starts at %d, want 0 (superblock + GDT)", rs[0].off)
	}
	for i := 1; i < len(rs); i++ {
		if rs[i].off <= rs[i-1].end {
			t.Fatalf("ranges not merged/sorted at %d: %v %v", i, rs[i-1], rs[i])
		}
	}
	t.Logf("%d extents, %d MiB forced", len(rs), total>>20)
}

func TestRangeSetOverlaps(t *testing.T) {
	s := &rangeSet{rs: []byteRange{{0, 4096}, {1 << 20, 2 << 20}, {10 << 20, 12 << 20}}}
	cases := []struct {
		off, end int64
		want     bool
	}{
		{0, 1 << 20, true},
		{1 << 20, 2 << 20, true},
		{2 << 20, 3 << 20, false},
		{9 << 20, 10 << 20, false},
		{9<<20 + 1, 10<<20 + 1, true},
		{12 << 20, 13 << 20, false},
		{100 << 20, 101 << 20, false},
	}
	for _, c := range cases {
		if got := s.overlaps(c.off, c.end); got != c.want {
			t.Fatalf("overlaps(%d,%d) = %v, want %v", c.off, c.end, got, c.want)
		}
	}
}

func TestMergeRanges(t *testing.T) {
	got := mergeRanges([]byteRange{{10, 20}, {0, 5}, {5, 10}, {30, 40}, {35, 45}})
	want := []byteRange{{0, 20}, {30, 45}}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if isPowerOf(9, 3) != true || isPowerOf(6, 3) != false || isPowerOf(1, 5) != true || isPowerOf(0, 7) != false {
		t.Fatal("isPowerOf wrong")
	}
}

func TestRewriteFlashpkgReal(t *testing.T) {
	if _, err := os.Stat(realFlashpkg); err != nil {
		t.Skip("real flashpkg not present")
	}
	if _, err := exec.LookPath("7z"); err != nil {
		t.Skip("7z not installed")
	}
	if _, err := mke2fsPath(); err != nil {
		t.Skip(err)
	}
	out := filepath.Join(t.TempDir(), "noerase.img")
	seq, err := RewriteFlashpkg(realFlashpkg, out, "erase-nvme")
	if err != nil {
		t.Fatal(err)
	}
	if seq != "bootloader\nexport-devices nvme0n1\nreboot\n" {
		t.Fatalf("sequence = %q", seq)
	}
	st, err := os.Stat(out)
	if err != nil || st.Size() != FlashpkgSize {
		t.Fatalf("out size: %v %d", err, st.Size())
	}
	// read it back the way the agent would see it
	dir := t.TempDir()
	if o, err := exec.Command("7z", "x", "-y", "-o"+dir, out, "-x!lost+found", "-x![SYS]").CombinedOutput(); err != nil {
		t.Fatalf("7z: %v\n%s", err, o)
	}
	got, err := os.ReadFile(filepath.Join(dir, "flashpkg", "conf", "command_sequence"))
	if err != nil || string(got) != seq {
		t.Fatalf("readback %q err %v", got, err)
	}
	bl, _ := filepath.Glob(filepath.Join(dir, "flashpkg", "bootloader", "*"))
	if len(bl) < 30 {
		t.Fatalf("bootloader payload not carried over: %d files", len(bl))
	}
	for _, must := range []string{"boot_device_type", "partitions.conf", "br_bct_BR.bct"} {
		if _, err := os.Stat(filepath.Join(dir, "flashpkg", "bootloader", must)); err != nil {
			t.Fatalf("missing bootloader/%s", must)
		}
	}
	t.Logf("%d bootloader files carried over", len(bl))
}
