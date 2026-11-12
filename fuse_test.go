package gotegra

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeN writes an n-byte file of 0xAB into dir and returns its full path.
func writeN(t *testing.T, dir, name string, n int) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, bytes.Repeat([]byte{0xAB}, n), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// fskpFixture lays out a dir with the six blobs an FSKP fuse burn needs, with
// distinct sizes so the plan can be checked, and returns their sizes by role.
func fskpFixture(t *testing.T) (dir string, sizes map[string]int) {
	t.Helper()
	dir = t.TempDir()
	sizes = map[string]int{
		"br_bct_BR.bct":                      16,
		"mb1_t234_sigheader.bin.encrypt":     32,
		"psc_bl1_t234_sigheader.bin.encrypt": 48,
		"mb1_bct_MB1_sigheader.bct.encrypt":  64,
		"mem_rcm_sigheader.bct.encrypt":      80,
		"blob.bin":                           8192,
	}
	for name, n := range sizes {
		writeN(t, dir, name, n)
	}
	return dir, sizes
}

func TestResolveAndBuildFSKPBurnPlan(t *testing.T) {
	dir, sizes := fskpFixture(t)

	bootBlobs, postBlobs, err := ResolveFuseBlobs(dir)
	if err != nil {
		t.Fatalf("ResolveFuseBlobs: %v", err)
	}
	if len(bootBlobs) != 4 {
		t.Fatalf("got %d boot blobs, want 4", len(bootBlobs))
	}
	// Boot order must be bct_br, mb1, psc_bl1, mb1_bct.
	wantOrder := []string{"br_bct_BR.bct", "mb1_t234_sigheader.bin.encrypt",
		"psc_bl1_t234_sigheader.bin.encrypt", "mb1_bct_MB1_sigheader.bct.encrypt"}
	for i, w := range wantOrder {
		if got := filepath.Base(bootBlobs[i]); got != w {
			t.Errorf("boot blob %d = %s, want %s", i, got, w)
		}
	}
	if filepath.Base(postBlobs[0]) != "mem_rcm_sigheader.bct.encrypt" {
		t.Errorf("post blob 0 = %s, want the mem BCT", filepath.Base(postBlobs[0]))
	}
	if filepath.Base(postBlobs[1]) != "blob.bin" {
		t.Errorf("post blob 1 = %s, want blob.bin", filepath.Base(postBlobs[1]))
	}

	plan, err := BuildFSKPBurnPlan(bootBlobs, postBlobs)
	if err != nil {
		t.Fatalf("BuildFSKPBurnPlan: %v", err)
	}
	if len(plan.BootBlobs) != 4 {
		t.Fatalf("plan has %d boot blobs, want 4", len(plan.BootBlobs))
	}
	if plan.BootBlobs[0].Size != int64(sizes["br_bct_BR.bct"]) {
		t.Errorf("bct_br size = %d, want %d", plan.BootBlobs[0].Size, sizes["br_bct_BR.bct"])
	}
	if plan.MemBCT.Size != int64(sizes["mem_rcm_sigheader.bct.encrypt"]) {
		t.Errorf("mem BCT size = %d, want %d", plan.MemBCT.Size, sizes["mem_rcm_sigheader.bct.encrypt"])
	}
	if plan.Blob.Size != int64(sizes["blob.bin"]) {
		t.Errorf("blob size = %d, want %d", plan.Blob.Size, sizes["blob.bin"])
	}
}

func TestFSKPBurnPlanString(t *testing.T) {
	dir, _ := fskpFixture(t)
	bootBlobs, postBlobs, err := ResolveFuseBlobs(dir)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildFSKPBurnPlan(bootBlobs, postBlobs)
	if err != nil {
		t.Fatal(err)
	}
	s := plan.String()
	for _, want := range []string{
		"pollbl", "--download bct_mem", "--download blob", "blob.bin",
		"BURNS THE FUSES", "br_bct_BR.bct",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plan string missing %q:\n%s", want, s)
		}
	}
}

func TestBuildFSKPBurnPlanBadCounts(t *testing.T) {
	if _, err := BuildFSKPBurnPlan([]string{"a", "b"}, []string{"m", "blob"}); err == nil {
		t.Error("accepted 2 boot blobs (want 4)")
	}
	if _, err := BuildFSKPBurnPlan([]string{"a", "b", "c", "d"}, []string{"blob"}); err == nil {
		t.Error("accepted 1 post blob (want 2)")
	}
}

func TestBuildFSKPBurnPlanMissingFile(t *testing.T) {
	// Well-formed counts but a path that does not exist → stat error, no panic.
	boot := []string{"/nope/a", "/nope/b", "/nope/c", "/nope/d"}
	post := []string{"/nope/mem", "/nope/blob"}
	if _, err := BuildFSKPBurnPlan(boot, post); err == nil {
		t.Error("expected a stat error for missing files")
	}
}

func TestResolveFuseBlobsMissing(t *testing.T) {
	if _, _, err := ResolveFuseBlobs(t.TempDir()); err == nil {
		t.Error("empty dir resolved without error")
	}
}
