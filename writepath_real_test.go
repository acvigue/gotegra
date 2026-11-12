//go:build darwin

package gotegra

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteRawImageRealRootfs runs the production rootfs write path (sparse,
// with the ext4 metadata ranges forced and the 512-byte tail padding) against
// a scratch FILE instead of /dev/rdiskN, then verifies the result equals the
// source byte for byte over the full logical size. Skipped unless the real
// image is present and GOTEGRA_REAL_WRITE_TEST=1 (it moves ~12 GiB).
func TestWriteRawImageRealRootfs(t *testing.T) {
	if os.Getenv("GOTEGRA_REAL_WRITE_TEST") != "1" {
		t.Skip("set GOTEGRA_REAL_WRITE_TEST=1")
	}
	src := realRootfs
	st, err := os.Stat(src)
	if err != nil {
		t.Skip("real rootfs image not present")
	}
	forced, err := Ext4MetadataRanges(src)
	if err != nil || len(forced) == 0 {
		t.Fatalf("ranges: %v %d", err, len(forced))
	}
	dir := "/Users/aiden/luka-flash/.writetest"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "rootfs-copy.img")
	defer os.RemoveAll(dir)
	// pre-size the target like an erased partition: all zeros, full length
	f, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(st.Size()); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := writeRawImage(src, dst, 0, true, forced); err != nil {
		t.Fatalf("writeRawImage: %v", err)
	}
	// verify
	a, _ := os.Open(src)
	b, _ := os.Open(dst)
	defer a.Close()
	defer b.Close()
	ba := make([]byte, 4<<20)
	bb := make([]byte, 4<<20)
	var off int64
	for {
		na, ea := io.ReadFull(a, ba)
		nb, eb := io.ReadFull(b, bb)
		if na != nb {
			t.Fatalf("length mismatch at %d: %d vs %d (%v %v)", off, na, nb, ea, eb)
		}
		if !bytes.Equal(ba[:na], bb[:nb]) {
			for i := 0; i < na; i++ {
				if ba[i] != bb[i] {
					t.Fatalf("content mismatch at byte %d", off+int64(i))
				}
			}
		}
		off += int64(na)
		if ea == io.EOF || ea == io.ErrUnexpectedEOF {
			break
		}
	}
	if off != st.Size() {
		t.Fatalf("verified %d of %d bytes", off, st.Size())
	}
	t.Logf("verified %d bytes identical; forced extents %d", off, len(forced))
}
