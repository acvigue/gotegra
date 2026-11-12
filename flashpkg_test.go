package gotegra

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSequence(t *testing.T) {
	si := ParseSequence("bootloader\nexport-devices nvme0n1\nreboot forced-recovery\n")
	if !si.Bootloader || !si.ExportsNvme || !si.Reboots || !si.ForcedRecovery {
		t.Fatalf("bad parse %+v", si)
	}
	si = ParseSequence("export-devices nvme0n1\nreboot\n")
	if si.Bootloader || !si.ExportsNvme || !si.Reboots || si.ForcedRecovery {
		t.Fatalf("bad parse %+v", si)
	}
}

func TestRewriteAddsAgentDirs(t *testing.T) {
	if _, err := exec.LookPath("7z"); err != nil {
		t.Skip("7z not installed")
	}
	if _, err := mke2fsPath(); err != nil {
		t.Skip(err)
	}
	img := filepath.Join(t.TempDir(), "p.img")
	if err := buildFlashpkg(img, "export-devices nvme0n1\nreboot\n"); err != nil {
		t.Fatal(err)
	}
	problems, err := LintFlashpkg(img)
	if err != nil || len(problems) != 0 {
		t.Fatalf("built package lint: %v %v", problems, err)
	}
	// a package without logs/ must be flagged
	bad := filepath.Join(t.TempDir(), "bad.img")
	tree := t.TempDir()
	os.MkdirAll(filepath.Join(tree, "flashpkg", "conf"), 0o755)
	os.WriteFile(filepath.Join(tree, "flashpkg", "conf", "command_sequence"), []byte("bootloader\nreboot\n"), 0o644)
	if err := buildFlashpkgFromTree(tree, bad); err != nil {
		t.Fatal(err)
	}
	problems, err = LintFlashpkg(bad)
	if err != nil || len(problems) == 0 {
		t.Fatalf("bad package not flagged: %v %v", problems, err)
	}
	t.Log(problems)
}

func TestCheckMB1BCT(t *testing.T) {
	conf := "BCT:0:1048576:br_bct_BR.bct\n" +
		"A_MB1_BCT:1835008:131072:mb1_cold.bct\n" +
		"A_MEM_BCT:1966080:262144:mem.bct\n" +
		"A_mb2:4325376:524288:mb2.bin\n" +
		"A_smm-fw:20578304:2097152:\n"
	good := make([]byte, 4096)
	copy(good[0x100:], []byte{0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00}) // A_MEM_BCT
	copy(good[0x200:], []byte{0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00}) // A_mb2
	reader := func(b []byte) func(string) ([]byte, error) {
		return func(name string) ([]byte, error) {
			if name != "mb1_cold.bct" {
				t.Errorf("read %q, want the A_MB1_BCT file", name)
			}
			return b, nil
		}
	}
	if p := checkMB1BCT(conf, reader(good)); p != nil {
		t.Errorf("good BCT flagged: %v", p)
	}
	if p := checkMB1BCT(conf, reader(make([]byte, 4096))); len(p) != 1 || !strings.Contains(p[0], "A_MEM_BCT, A_mb2") {
		t.Errorf("zeroed BCT not flagged for both: %v", p)
	}
	if p := checkMB1BCT("mmc:0:512:x.bin\n", reader(nil)); p != nil {
		t.Errorf("layout without A_MB1_BCT must be skipped: %v", p)
	}
}
