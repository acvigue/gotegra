package gotegra

import (
	"path/filepath"
	"strings"
	"testing"
)

// The file names of a real PKC-signed flashpack (luka-firmware 0.1.0+3685e44,
// ci/flashpack.sh with a PKC key) and of the zero-key one of the same commit.
var (
	pkcNames = []string{
		"br_bct_BR.bct",
		"mb1_t234_prod_aligned_sigheader.bin.signed",
		"psc_bl1_t234_prod_aligned_sigheader.bin.signed",
		"mb1_bct_MB1_sigheader.bct.signed",
		"mem_rcm_sigheader.bct.signed",
		"blob.bin",
	}
	zeroKeyNames = []string{
		"br_bct_BR.bct",
		"mb1_t234_prod_aligned_sigheader.bin.encrypt",
		"psc_bl1_t234_prod_aligned_sigheader.bin.encrypt",
		"mb1_bct_MB1_sigheader.bct.encrypt",
		"mem_rcm_sigheader.bct.encrypt",
		"blob.bin",
	}
)

func blobDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		writeN(t, dir, n, 16)
	}
	return dir
}

func bases(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

func TestResolveFlashBootBlobsBothSignings(t *testing.T) {
	for _, tc := range []struct {
		names   []string
		signing string
	}{
		{zeroKeyNames, SignedZeroKey},
		{pkcNames, SignedPKC},
	} {
		// rcmbootcmd.txt ships in the directory too and must not disturb anything
		dir := blobDir(t, append([]string{"rcmbootcmd.txt"}, tc.names...)...)
		boot, post, err := ResolveFlashBootBlobs(dir)
		if err != nil {
			t.Fatalf("%s: %v", tc.signing, err)
		}
		got := strings.Join(append(bases(boot), bases(post)...), " ")
		if want := strings.Join(tc.names, " "); got != want {
			t.Errorf("%s: resolved\n  %s\nwant\n  %s", tc.signing, got, want)
		}
		if s := BlobSigning(boot); s != tc.signing {
			t.Errorf("BlobSigning = %q, want %q", s, tc.signing)
		}
	}
}

func TestResolveRcmBlobsPKC(t *testing.T) {
	dir := blobDir(t, append([]string{"applet_t234_sigheader.bin.signed"}, pkcNames...)...)
	boot, applet, err := ResolveRcmBlobs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(bases(boot), " "), strings.Join(pkcNames[:4], " "); got != want {
		t.Errorf("boot blobs %s, want %s", got, want)
	}
	if filepath.Base(applet) != "applet_t234_sigheader.bin.signed" {
		t.Errorf("applet = %s", filepath.Base(applet))
	}
}

// A plain and a PKC build of one commit copied into the same directory: the
// PKC build's br_bct_BR.bct and blob.bin next to both kinds of the rest. Picking
// the *.encrypt files out of that would send a set no unit boots.
func TestResolveRefusesMixedDirectory(t *testing.T) {
	dir := blobDir(t, append(append([]string{}, zeroKeyNames...), pkcNames...)...)
	_, _, err := ResolveFlashBootBlobs(dir)
	if err == nil {
		t.Fatal("a directory with both *.encrypt and *.signed files was accepted")
	}
	for _, w := range []string{"*.encrypt", "*.signed"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not name %s", err, w)
		}
	}
	// one stray file of the other kind is a mix too
	dir = blobDir(t, append([]string{"mem_rcm_sigheader.bct.encrypt"}, pkcNames...)...)
	if _, _, err := ResolveFlashBootBlobs(dir); err == nil {
		t.Error("a PKC directory with one zero-key file was accepted")
	}
}

func TestResolveNamesTheMissingBlob(t *testing.T) {
	// PKC set without the memory BCT: the error names it, in the PKC spelling only
	dir := blobDir(t, pkcNames[0], pkcNames[1], pkcNames[2], pkcNames[3], pkcNames[5])
	_, _, err := ResolveFlashBootBlobs(dir)
	if err == nil || !strings.Contains(err.Error(), "bct_mem") {
		t.Fatalf("want an error naming bct_mem, got %v", err)
	}
	if strings.Contains(err.Error(), ".encrypt") {
		t.Errorf("error for a PKC set mentions .encrypt: %v", err)
	}
	// nothing signed at all: both spellings are named
	dir = blobDir(t, "br_bct_BR.bct", "blob.bin")
	_, _, err = ResolveFlashBootBlobs(dir)
	if err == nil || !strings.Contains(err.Error(), ".encrypt") || !strings.Contains(err.Error(), ".signed") {
		t.Errorf("want an error naming both spellings, got %v", err)
	}
	// no BCT, no blob.bin
	if _, _, err := ResolveFlashBootBlobs(blobDir(t, pkcNames[1:5]...)); err == nil || !strings.Contains(err.Error(), "bct_br") {
		t.Errorf("want an error naming bct_br, got %v", err)
	}
	if _, _, err := ResolveFlashBootBlobs(blobDir(t, pkcNames[:5]...)); err == nil || !strings.Contains(err.Error(), "blob") {
		t.Errorf("want an error naming blob, got %v", err)
	}
}

func TestFuseModeAndCheckSigning(t *testing.T) {
	const (
		cidNS      = "0x80012344705DD3D10000000000000000" // an unfused Orin NX
		cidPKC     = "0x81012344705DD3D10000000000000000"
		cidSBKPKC  = "0x89012344705DD3D10000000000000000"
		cidNonProd = "0x00012344705DD3D10000000000000000"
		cidOdd     = "0x87012344705DD3D10000000000000000"
	)
	for cid, want := range map[string]string{
		cidNS: FuseNS, cidPKC: FusePKC, cidSBKPKC: FuseSBKPKC, cidNonProd: "", cidOdd: "", "0x12": "",
	} {
		if got := FuseMode(cid); got != want {
			t.Errorf("FuseMode(%s) = %q, want %q", cid, got, want)
		}
	}
	for cid, want := range map[string]string{
		cidNS:      "NS (unfused, no secure-boot fuses)",
		cidPKC:     "PKC (public-key secure boot)",
		cidSBKPKC:  "SBKPKC (SBK + secure boot)",
		cidNonProd: "non-production chip",
		cidOdd:     "unrecognized (0x870)",
	} {
		if got, ok := DecodeFuseState(cid); !ok || got != want {
			t.Errorf("DecodeFuseState(%s) = %q, %v; want %q", cid, got, ok, want)
		}
	}
	if _, ok := DecodeFuseState("0x12"); ok {
		t.Error("DecodeFuseState accepted a short CID")
	}

	zero, pkc := zeroKeyNames[:4], pkcNames[:4]
	for _, tc := range []struct {
		cid   string
		blobs []string
		ok    bool
	}{
		{cidNS, zero, true},
		{cidNS, pkc, false},
		{cidPKC, pkc, true},
		{cidPKC, zero, false},
		{cidSBKPKC, zero, false},
		{cidSBKPKC, pkc, true},
		{cidNonProd, pkc, true}, // unknown state: not ours to judge
		{cidOdd, zero, true},
		{cidNS, []string{"br_bct_BR.bct"}, true}, // nothing signed in the list
	} {
		err := CheckSigning(tc.cid, tc.blobs)
		if (err == nil) != tc.ok {
			t.Errorf("CheckSigning(%s, %s) = %v, want ok=%v", tc.cid, BlobSigning(tc.blobs), err, tc.ok)
		}
	}
}
